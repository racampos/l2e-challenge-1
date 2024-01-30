import {
  SmartContract,
  Poseidon,
  Field,
  State,
  state,
  PublicKey,
  Mina,
  method,
  UInt32,
  PrivateKey,
  AccountUpdate,
  MerkleTree,
  MerkleWitness,
  Struct,
} from 'o1js';

const doProofs = true;

class ElligibleAddressMerkleWitness extends MerkleWitness(8) { }
class MessageMerkleWitness extends MerkleWitness(8) { }

class Address extends Struct({
  publicKey: PublicKey,
}) {
  hash(): Field {
    return Poseidon.hash(Address.toFields(this));
  }
}

class Message extends Struct({
  publicKey: PublicKey,
  data: Field,
}) {
  hash(): Field {
    return Poseidon.hash(Message.toFields(this));
  }
}

export class MessageManager extends SmartContract {
  @state(Field) eligibleAddressesCommitment = State<Field>();
  @state(Field) messagesCommitment = State<Field>();

  @method init() {
    super.init();
    this.eligibleAddressesCommitment.set(Field(0));
    this.messagesCommitment.set(Field(0));
  }

  @method addEligibleAddress(address: Address, path: ElligibleAddressMerkleWitness) {
    // Validate that there is room for another address (i.e. there are less than 100 addresses)
    const count = path.calculateIndex();
    count.assertLessThan(Field(100));

    let newCommitment = path.calculateRoot(address.hash());
    this.eligibleAddressesCommitment.set(newCommitment);
  }

  @method depositMessage(address: Address, message: Message, eligibleAddressPath: ElligibleAddressMerkleWitness, messagePath: MessageMerkleWitness) {
    // we fetch the on-chain commitment for the Elligible Addresses Merkle Tree
    this.eligibleAddressesCommitment.requireEquals(this.eligibleAddressesCommitment.get());

    // we check that the address is within the committed Elligible Addresses Merkle Tree
    eligibleAddressPath.calculateRoot(address.hash()).assertEquals(this.eligibleAddressesCommitment.get());

    // Validate the message against the other criteria
    // ...

    // we calculate the new Merkle Root and set it
    let newCommitment = messagePath.calculateRoot(message.hash());
    this.messagesCommitment.set(newCommitment);
  }
}

let Local = Mina.LocalBlockchain({ proofsEnabled: doProofs });
Mina.setActiveInstance(Local);
let initialBalance = 10_000_000_000;

let feePayerKey = Local.testAccounts[0].privateKey;
let feePayer = Local.testAccounts[0].publicKey;

// the zkapp account
let zkappKey = PrivateKey.random();
let zkappAddress = zkappKey.toPublicKey();

// Off-chain storage for address-message pairs
const messages: Map<PublicKey, Field> = new Map<PublicKey, Field>();

// Off-chain storage for eligible addresses
const eligibleAddresses: Array<PublicKey> = new Array<PublicKey>();

// we now need "wrap" the Merkle tree around our off-chain storage
// we initialize a new Merkle Tree with height 8
const EligibleAddressTree = new MerkleTree(8);
const MessageTree = new MerkleTree(8);

let messageManagerZkApp = new MessageManager(zkappAddress);
console.log('Deploying Message Manager..');
if (doProofs) {
  await MessageManager.compile();
}
let tx = await Mina.transaction(feePayer, () => {
  AccountUpdate.fundNewAccount(feePayer).send({
    to: zkappAddress,
    amount: initialBalance,
  });
  messageManagerZkApp.deploy();
});
await tx.prove();
await tx.sign([feePayerKey, zkappKey]).send();

console.log('Adding an eligible address..');
await addEligibleAddress(Local.testAccounts[1].publicKey);

console.log('Depositing a message..');
await depositMessage(Local.testAccounts[1].publicKey, Field(123));

console.log('Message Deposited!')

async function addEligibleAddress(a: PublicKey) {
  const eligibleAddressesLeafCount = BigInt(eligibleAddresses.length);
  const w = EligibleAddressTree.getWitness(eligibleAddressesLeafCount);

  const witness = new ElligibleAddressMerkleWitness(w);
  const address = new Address({ publicKey: a });
  const tx = await Mina.transaction(feePayer, () => {
    messageManagerZkApp.addEligibleAddress(address, witness);
  });
  await tx.prove();
  await tx.sign([feePayerKey, zkappKey]).send();

  // if the transaction was successful, we can update our off-chain storage as well
  eligibleAddresses.push(a);
  // EligibleAddressTree.setLeaf(index.toBigInt(), address.hash());
  EligibleAddressTree.setLeaf(eligibleAddressesLeafCount, address.hash());
  messageManagerZkApp.eligibleAddressesCommitment.get().assertEquals(EligibleAddressTree.getRoot());
}

async function depositMessage(a: PublicKey, m: Field) {
  const addressIndex = eligibleAddresses.indexOf(a);
  const aw = EligibleAddressTree.getWitness(BigInt(addressIndex));

  const addressWitness = new ElligibleAddressMerkleWitness(aw);

  const messagesLeafCount = BigInt(messages.size)
  let mw = MessageTree.getWitness(messagesLeafCount);
  const messageWitness = new MessageMerkleWitness(mw);



  const address = new Address({ publicKey: a });
  const message = new Message({ publicKey: a, data: m });
  const tx = await Mina.transaction(feePayer, () => {
    messageManagerZkApp.depositMessage(address, message, addressWitness, messageWitness);
  });
  await tx.prove();
  await tx.sign([feePayerKey, zkappKey]).send();

  // if the transaction was successful, we can update our off-chain storage as well
  messages.set(a, m);
  MessageTree.setLeaf(messagesLeafCount, message.hash());
  messageManagerZkApp.messagesCommitment.get().assertEquals(MessageTree.getRoot());
}
