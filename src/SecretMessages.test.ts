import {
  Poseidon,
  Field,
  PublicKey,
  Mina,
  PrivateKey,
  AccountUpdate,
  MerkleTree,
  MerkleWitness,
  Struct,
  UInt32,
  MerkleMap,
  Nullifier,
} from 'o1js';
import { MessageManager } from './SecretMessages';

interface SenderAccountInfo {
  privateKey: PrivateKey;
  publicKey: PublicKey;
}

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

const proofsEnabled = false;

describe('MessageManager.test.ts', () => {
  let zkApp: MessageManager,
    zkAppAddress: PublicKey,
    zkAppPrivKey: PrivateKey,
    senderAccounts: Array<SenderAccountInfo>,
    deployerAcc: PublicKey,
    deployerAccPrivKey: PrivateKey,
    messages: Map<PublicKey, Field>,
    eligibleAddresses: Array<PublicKey>,
    messageTree: MerkleTree,
    eligibleAddressesTree: MerkleTree,
    nullifier: Nullifier,
    nullifierTree: MerkleMap;

  beforeAll(async () => {
    proofsEnabled && (await MessageManager.compile());

    const localBlockchain = Mina.LocalBlockchain({ proofsEnabled: false });
    Mina.setActiveInstance(localBlockchain);

    senderAccounts = new Array<SenderAccountInfo>();

    for (let i = 0; i < 100; i++) {
      const privateKey = PrivateKey.random();
      const publicKey = privateKey.toPublicKey();
      senderAccounts.push({ privateKey, publicKey });
    }
  });

  async function localDeploy() {
    const nullifierMessage = Field(5);
    messageTree = new MerkleTree(8);
    eligibleAddressesTree = new MerkleTree(8);
    nullifierTree = new MerkleMap();

    const jsonNullifier = Nullifier.createTestNullifier(
      [nullifierMessage],
      deployerAccPrivKey
    );

    nullifier = Nullifier.fromJSON(jsonNullifier);

    const txn = await Mina.transaction(deployerAcc, () => {
      AccountUpdate.fundNewAccount(deployerAcc);
      zkApp.deploy({ zkappKey: zkAppPrivKey });

      zkApp.nullifierRoot.set(nullifierTree.getRoot());
      zkApp.nullifierMessage.set(nullifierMessage);
      zkApp.eligibleAddressesCommitment.set(Field(0));
      zkApp.messagesCommitment.set(Field(0));
    });
    await txn.prove();
    await txn.sign([deployerAccPrivKey, zkAppPrivKey]).send();
  }

  function initAddEligibleAddress(
    a: PublicKey,
    eligibleAddresses: Array<PublicKey>
  ) {
    const eligibleAddressesLeafCount = BigInt(eligibleAddresses.length);
    const w = eligibleAddressesTree.getWitness(eligibleAddressesLeafCount);

    const witness = new ElligibleAddressMerkleWitness(w);
    const address = new Address({ publicKey: a });
    eligibleAddressesTree.setLeaf(eligibleAddressesLeafCount, address.hash());

    return {
      newEligibleAddresses: eligibleAddresses,
      address,
      witness,
    };

    // if the transaction was successful, we can update our off-chain storage as well
    // eligibleAddresses.push(a);
    // EligibleAddressTree.setLeaf(index.toBigInt(), address.hash());
    // eligibleAddressesTree.setLeaf(eligibleAddressesLeafCount, address.hash());
  }

  async function initDepositMessage(
    a: PublicKey,
    m: Field,
    voidAddressCheck = false
  ) {
    const addressIndex = eligibleAddresses.indexOf(a);
    if (!voidAddressCheck && addressIndex === -1) {
      throw new Error('Address not found in eligibleAddresses');
    }
    const aw = eligibleAddressesTree.getWitness(BigInt(addressIndex));

    const addressWitness = new ElligibleAddressMerkleWitness(aw);

    const messagesLeafCount = BigInt(messages.size);
    let mw = messageTree.getWitness(messagesLeafCount);
    const messageWitness = new MessageMerkleWitness(mw);

    const address = new Address({ publicKey: a });
    const message = new Message({ publicKey: a, data: m });

    return {
      address,
      message,
      addressWitness,
      messageWitness,
    };
  }

  async function performAddEligibleAddress(senderAcc: PublicKey) {
    const { address, witness, newEligibleAddresses } = initAddEligibleAddress(
      senderAcc,
      eligibleAddresses
    );

    const tx = await Mina.transaction(deployerAcc, () => {
      zkApp.addEligibleAddress(address, witness);
    });
    await tx.prove();
    await tx.sign([deployerAccPrivKey]).send();

    eligibleAddresses.push(senderAcc);

    return { address, witness, newEligibleAddresses };
  }

  async function performDepositMessage(senderAcc: PublicKey, message: Field) {
    const {
      address,
      message: msg,
      addressWitness,
      messageWitness,
    } = await initDepositMessage(senderAcc, message);

    const tx = await Mina.transaction(deployerAcc, () => {
      zkApp.depositMessage(
        address,
        msg,
        addressWitness,
        messageWitness,
        nullifier
      );
    });
    await tx.prove();
    await tx.sign([deployerAccPrivKey]).send();

    messages.set(senderAcc, message);
    messageTree.setLeaf(BigInt(messages.size), msg.hash());
  }

  async function handleMultipleAddEligibleAddresses(
    accounts: Array<SenderAccountInfo>
  ) {
    for (const senderAcc of accounts) {
      const { address, witness } = initAddEligibleAddress(
        senderAcc.publicKey,
        eligibleAddresses
      );

      const txAdd = await Mina.transaction(deployerAcc, () => {
        zkApp.addEligibleAddress(address, witness);
      });

      await txAdd.prove();
      await txAdd.sign([deployerAccPrivKey, zkAppPrivKey]).send();

      // After the transaction is sent and confirmed, push the publicKey to eligibleAddresses
      eligibleAddresses.push(senderAcc.publicKey);
    }

    return eligibleAddresses;
  }

  describe('MessageManager.test.ts', () => {
    beforeEach(async () => {
      const localBlockchain = Mina.LocalBlockchain({ proofsEnabled });
      Mina.setActiveInstance(localBlockchain);
      ({ privateKey: deployerAccPrivKey, publicKey: deployerAcc } =
        localBlockchain.testAccounts[0]);

      eligibleAddresses = new Array<PublicKey>();
      messages = new Map<PublicKey, Field>();

      zkAppPrivKey = PrivateKey.random();
      zkAppAddress = zkAppPrivKey.toPublicKey();
      zkApp = new MessageManager(zkAppAddress);
    });

    it('generates and deploys MessageManager contract', async () => {
      await localDeploy();
      const eligibleAddressesCommitment =
        zkApp.eligibleAddressesCommitment.get();
      expect(eligibleAddressesCommitment).toEqual(Field(0));
    });

    it('should be able to add an address to registered addresses', async () => {
      await localDeploy();
      const senderAcc = senderAccounts[0].publicKey;
      const { address, witness } = initAddEligibleAddress(
        senderAcc,
        eligibleAddresses
      );

      expect(async () => {
        const tx = await Mina.transaction(deployerAcc, () => {
          zkApp.addEligibleAddress(address, witness);
        });
        await tx.prove();
        await tx.sign([deployerAccPrivKey]).send();
      });
    });

    it('a registered address can deposit a correct message', async () => {
      await localDeploy();
      const senderAcc = senderAccounts[0].publicKey;

      const { address } = await performAddEligibleAddress(senderAcc);

      const m = Field(32);
      const { message, addressWitness, messageWitness } =
        await initDepositMessage(senderAcc, m);

      expect(async () => {
        const tx = await Mina.transaction(deployerAcc, () => {
          zkApp.depositMessage(
            address,
            message,
            addressWitness,
            messageWitness,
            nullifier
          );
        });
        await tx.prove();
        return await tx.sign([deployerAccPrivKey]).send();
      });
    });

    it('an event is emitted when a correct message is deposited', async () => {
      await localDeploy();
      const senderAcc = senderAccounts[0].publicKey;
      const { address, witness } = initAddEligibleAddress(
        senderAcc,
        eligibleAddresses
      );

      const tx1 = await Mina.transaction(deployerAcc, () => {
        zkApp.addEligibleAddress(address, witness);
      });
      await tx1.prove();
      await tx1.sign([deployerAccPrivKey]).send();

      eligibleAddresses.push(senderAcc);

      const m = Field(32);
      const { message, addressWitness, messageWitness } =
        await initDepositMessage(senderAcc, m);

      const tx2 = await Mina.transaction(deployerAcc, () => {
        zkApp.depositMessage(
          address,
          message,
          addressWitness,
          messageWitness,
          nullifier
        );
      });
      await tx2.prove();
      await tx2.sign([deployerAccPrivKey]).send();

      const events = await zkApp.fetchEvents(UInt32.from(0), UInt32.from(1));

      expect(events.length).toBeGreaterThanOrEqual(1);

      const event = events[0];

      const eventField = event.event.data.toFields(null)[0];

      eventField.assertEquals(message.data);
    });

    it('any randomly selected registered address (out of 100) can deposit a valid message', async () => {
      await localDeploy();

      return handleMultipleAddEligibleAddresses(senderAccounts).then(
        async (addresses) => {
          expect(addresses.length).toEqual(senderAccounts.length);

          const appCommitment = zkApp.eligibleAddressesCommitment.get();

          appCommitment.assertEquals(eligibleAddressesTree.getRoot());

          const randomIndex = Math.floor(Math.random() * addresses.length);

          const randomPublicKy = addresses[randomIndex];
          const m = Field(32);

          const { address, message, addressWitness, messageWitness } =
            await initDepositMessage(randomPublicKy, m);

          const depositMsg = await Mina.transaction(deployerAcc, () => {
            zkApp.depositMessage(
              address,
              message,
              addressWitness,
              messageWitness,
              nullifier
            );
          });

          await depositMsg.prove();
          await depositMsg.sign([deployerAccPrivKey]).send();
          const events = await zkApp.fetchEvents(
            UInt32.from(0),
            UInt32.from(1)
          );

          expect(events.length).toBeGreaterThanOrEqual(1);

          const event = events[0];

          const eventField = event.event.data.toFields(null)[0];

          return eventField.assertEquals(message.data);
        }
      );
    });

    it('should prevent an unregistered address from depositing a message', async () => {
      await localDeploy();
      const senderAcc = senderAccounts[0].publicKey;

      const m = Field(32);
      const { message, addressWitness, messageWitness } =
        await initDepositMessage(senderAcc, m, true);

      // overide 'address' with an unregistered one
      const privateKey = PrivateKey.random();
      const publicKey = privateKey.toPublicKey();
      const unregisteredAddress = new Address({ publicKey: publicKey });

      expect(async () => {
        await Mina.transaction(deployerAcc, () => {
          zkApp.depositMessage(
            unregisteredAddress,
            message,
            addressWitness,
            messageWitness,
            nullifier
          );
        });
        // await tx.prove();
        // return await tx.sign([deployerAccPrivKey]).send();
      }).rejects.toThrow(
        'address is not in the committed Eligible Addresses Merkle Tree'
      );
    });

    it('should not allow depositing a message that does not complies with rule #1', async () => {
      await localDeploy();
      const senderAcc = senderAccounts[0].publicKey;

      await performAddEligibleAddress(senderAcc);

      // This is a wrong message as per the first rule (33 = 0b100001)
      // namely, if flag 1 is true, then all other flags must be false
      const wrongMessage = Field(33);
      const { address, message, addressWitness, messageWitness } =
        await initDepositMessage(senderAcc, wrongMessage);

      return expect(async () => {
        await Mina.transaction(deployerAcc, () => {
          zkApp.depositMessage(
            address,
            message, // This is a wrong message
            addressWitness,
            messageWitness,
            nullifier
          );
        });
      }).rejects.toThrow('flag 1 is true, and all other flags are not false');
    });

    it('should not allow depositing a message that does not complies with rule #2', async () => {
      await localDeploy();
      const senderAcc = senderAccounts[0].publicKey;

      await performAddEligibleAddress(senderAcc);

      // This is a wrong message as per the second rule (16 = 0b010000)
      // namely, if flag 2 is true, then flag 3 must also be true.
      const wrongMessage = Field(16);
      const { address, message, addressWitness, messageWitness } =
        await initDepositMessage(senderAcc, wrongMessage);

      return expect(async () => {
        await Mina.transaction(deployerAcc, () => {
          zkApp.depositMessage(
            address,
            message, // This is a wrong message
            addressWitness,
            messageWitness,
            nullifier
          );
        });
      }).rejects.toThrow('flag 2 is true, and flag 3 is not true');
    });

    it('should not allow depositing a message that does not complies with rule #3', async () => {
      await localDeploy();
      const senderAcc = senderAccounts[0].publicKey;

      await performAddEligibleAddress(senderAcc);

      // This is a wrong message as per the third rule (5 = 0b000101)
      // namely, if flag 4 is true, then flags 5 and 6 must be false.
      const wrongMessage = Field(5);
      const { address, message, addressWitness, messageWitness } =
        await initDepositMessage(senderAcc, wrongMessage);

      return expect(async () => {
        await Mina.transaction(deployerAcc, () => {
          zkApp.depositMessage(
            address,
            message, // This is a wrong message
            addressWitness,
            messageWitness,
            nullifier
          );
        });
      }).rejects.toThrow(
        'flag 4 is true, and either flag 5 and 6 are not false'
      );
    });

    it('should prevent an address from depositing a message if it has already deposited one', async () => {
      await localDeploy();
      const senderAcc = senderAccounts[0].publicKey;

      await performAddEligibleAddress(senderAcc);

      const m = Field(32);

      await performDepositMessage(senderAcc, m);

      const address = new Address({ publicKey: senderAcc });
      const message = new Message({ publicKey: senderAcc, data: m });

      const {
        addressWitness: newAddressWitness,
        messageWitness: newMessageWitness,
      } = await initDepositMessage(senderAcc, m);

      // Attempt to deposit a second message
      return expect(async () => {
        await Mina.transaction(deployerAcc, () => {
          zkApp.depositMessage(
            address,
            message,
            newAddressWitness,
            newMessageWitness,
            nullifier
          );
        });
      }).rejects;
    });
  });
});
