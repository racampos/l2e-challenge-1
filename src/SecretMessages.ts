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

class ElligibleAddressMerkleWitness extends MerkleWitness(8) {}
class MessageMerkleWitness extends MerkleWitness(8) {}

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
  @state(Field) eligibleAddressCount = State<Field>();
  @state(Field) messageCount = State<Field>();

  @method init() {
    super.init();
    this.eligibleAddressesCommitment.set(Field(0));
    this.messagesCommitment.set(Field(0));
    this.eligibleAddressCount.set(Field(0));
    this.messageCount.set(Field(0));
  }

  @method addEligibleAddress(address: Address, path: ElligibleAddressMerkleWitness) {
    // Validate that there is room for another address (i.e. there are less than 100 addresses)
    let count = this.eligibleAddressCount.get();
    this.eligibleAddressCount.requireEquals(this.eligibleAddressCount.get());
    count.assertLessThan(Field(100));
    
    // we calculate the new Merkle Root and set it
    let newCommitment = path.calculateRoot(address.hash());
    this.eligibleAddressesCommitment.set(newCommitment);

    // we increment the count
    this.eligibleAddressCount.set(count.add(1));
  }

  @method depositMessage(address: Address, message: Message, eligibleAddressPath: ElligibleAddressMerkleWitness, messagePath: MessageMerkleWitness) {
    // we fetch the on-chain commitment for the Elligible Addresses Merkle Tree
    let eligibleAddressesCommitment = this.eligibleAddressesCommitment.get();
    this.eligibleAddressesCommitment.requireEquals(eligibleAddressesCommitment);

    // we check that the address is within the committed Elligible Addresses Merkle Tree
    eligibleAddressPath.calculateRoot(address.hash()).assertEquals(eligibleAddressesCommitment);

    // Validate the message against the other criteria
    // ...

    // we calculate the new Merkle Root and set it
    let newCommitment = messagePath.calculateRoot(message.hash());
    this.messagesCommitment.set(newCommitment);

    // we increment the count
    let count = this.messageCount.get();
    this.messageCount.requireEquals(this.messageCount.get());
    this.messageCount.set(count.add(1));
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
let Messages: Map<PublicKey, Field> = new Map<PublicKey, Field>();

// Off-chain storage for eligible addresses
let EligibleAddresses: Array<PublicKey> = new Array<PublicKey>();

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

async function addEligibleAddress(a: PublicKey) {
  let index = messageManagerZkApp.eligibleAddressCount.get();
  let w = EligibleAddressTree.getWitness(index.toBigInt());
  let witness = new ElligibleAddressMerkleWitness(w);
  let address = new Address({ publicKey: a });
  let tx = await Mina.transaction(feePayer, () => {
    messageManagerZkApp.addEligibleAddress(address, witness);
  });
  await tx.prove();
  await tx.sign([feePayerKey, zkappKey]).send();

  // if the transaction was successful, we can update our off-chain storage as well
  EligibleAddresses.push(a);
  EligibleAddressTree.setLeaf(index.toBigInt(), address.hash());
  messageManagerZkApp.eligibleAddressesCommitment.get().assertEquals(EligibleAddressTree.getRoot());
}

async function depositMessage(a: PublicKey, m: Field) {
  let addressIndex = messageManagerZkApp.eligibleAddressCount.get();
  let aw = EligibleAddressTree.getWitness(addressIndex.toBigInt());
  let addressWitness = new ElligibleAddressMerkleWitness(aw);

  let messageIndex = messageManagerZkApp.messageCount.get();
  let mw = MessageTree.getWitness(messageIndex.toBigInt());
  let messageWitness = new MessageMerkleWitness(mw);
  
  let address = new Address({ publicKey: a });
  let message = new Message({ publicKey: a, data: m });
  let tx = await Mina.transaction(feePayer, () => {
    messageManagerZkApp.depositMessage(address, message, addressWitness, messageWitness);
  });
  await tx.prove();
  await tx.sign([feePayerKey, zkappKey]).send();

  // if the transaction was successful, we can update our off-chain storage as well
  Messages.set(a, m);
  MessageTree.setLeaf(messageIndex.toBigInt(), message.hash());
  messageManagerZkApp.messagesCommitment.get().assertEquals(MessageTree.getRoot());
}