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
  // fetchEvents,
  UInt32,
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

describe('SecretMessages.test.js', () => {
  let zkApp: MessageManager,
    zkAppAddress: PublicKey,
    zkAppPrivKey: PrivateKey,
    senderAccounts: Array<SenderAccountInfo>,
    deployerAcc: PublicKey,
    deployerAccPrivKey: PrivateKey,
    messages: Map<PublicKey, Field>,
    eligibleAddresses: Array<PublicKey>,
    messageTree: MerkleTree,
    eligibleAddressesTree: MerkleTree;
  // elligibleAddressMerkleWitness: ElligibleAddressMerkleWitness extends
  //   typeof MerkleWitness,
  // messageMerkleWitness: MessageMerkleWitness extends typeof MerkleWitness;

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

    messageTree = new MerkleTree(8);
    eligibleAddressesTree = new MerkleTree(8);
  });

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

  async function localDeploy(prove: boolean = false, wait: boolean = false) {
    const txn = await Mina.transaction(deployerAcc, () => {
      AccountUpdate.fundNewAccount(deployerAcc);
      zkApp.deploy({ zkappKey: zkAppPrivKey });
    });
    prove = true;
    if (prove) {
      await txn.prove();
    }
    // this tx needs .sign(), because `deploy()` adds an account update that requires signature authorization
    // const txPromise = await txn.sign([deployerAccPrivKey, zkAppPrivKey]).send();
    await txn.sign([deployerAccPrivKey, zkAppPrivKey]).send();

    if (wait) {
      // await txPromise.wait();
    }
  }

  function initAddEligibleAddress(a: PublicKey) {
    const eligibleAddressesLeafCount = BigInt(eligibleAddresses.length);
    const w = eligibleAddressesTree.getWitness(eligibleAddressesLeafCount);

    const witness = new ElligibleAddressMerkleWitness(w);
    const address = new Address({ publicKey: a });
    eligibleAddressesTree.setLeaf(eligibleAddressesLeafCount, address.hash());

    return {
      address,
      witness,
    };

    // if the transaction was successful, we can update our off-chain storage as well
    // eligibleAddresses.push(a);
    // EligibleAddressTree.setLeaf(index.toBigInt(), address.hash());
    // eligibleAddressesTree.setLeaf(eligibleAddressesLeafCount, address.hash());
  }

  async function initDepositMessage(a: PublicKey, m: Field) {
    const addressIndex = eligibleAddresses.indexOf(a);
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

  describe('MessageManager.test.ts', () => {
    it('generates and deploys MessageManager contract', async () => {
      await localDeploy();
      const eligibleAddressesCommitment =
        zkApp.eligibleAddressesCommitment.get();
      expect(eligibleAddressesCommitment).toEqual(Field(0));
    });

    it('should be able to add an address to registered addresses', async () => {
      await localDeploy();
      const senderAcc = senderAccounts[0].publicKey;
      const { address, witness } = await initAddEligibleAddress(senderAcc);

      expect(async () => {
        await Mina.transaction(deployerAcc, () => {
          zkApp.addEligibleAddress(address, witness);
        });
      }).resolves;
    });

    it('a registered address can deposit a correct message', async () => {
      await localDeploy();
      const senderAcc = senderAccounts[0].publicKey;
      const { address, witness } = await initAddEligibleAddress(senderAcc);

      await Mina.transaction(deployerAcc, () => {
        zkApp.addEligibleAddress(address, witness);
      });

      const m = Field(32);
      const { message, addressWitness, messageWitness } =
        await initDepositMessage(senderAcc, m);

      expect(async () => {
        await Mina.transaction(deployerAcc, () => {
          zkApp.depositMessage(
            address,
            message,
            addressWitness,
            messageWitness
          );
        });
      }).resolves;
    });

    it('an event is emitted when a correct message is deposited', async () => {
      await localDeploy();
      const senderAcc = senderAccounts[0].publicKey;
      const { address, witness } = initAddEligibleAddress(senderAcc);

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
        zkApp.depositMessage(address, message, addressWitness, messageWitness);
      });
      await tx2.prove();
      await tx2.sign([deployerAccPrivKey]).send();

      const events = await zkApp.fetchEvents(UInt32.from(0), UInt32.from(1));

      expect(events.length).toBeGreaterThanOrEqual(1);

      const event = events[0];

      const eventField = event.event.data.toFields(null)[0];

      eventField.assertEquals(message.data);
      // event.event.data.check(event.event.data);
    });

    it('any randomly selected registered address (out of 100) can deposit a valid message', async () => {
      await localDeploy();

      // const txs = [];

      senderAccounts.map(async (senderAcc) => {
        const { address, witness } = initAddEligibleAddress(
          senderAcc.publicKey
        );

        eligibleAddresses.push(senderAcc.publicKey);

        const txAdd = await Mina.transaction(deployerAcc, () => {
          zkApp.addEligibleAddress(address, witness);
        });
        await txAdd.prove();
        const sent = await txAdd
          .sign([deployerAccPrivKey, zkAppPrivKey])
          .send();
        // .then(() => {
        //   console.log(':(((((');
        //   eligibleAddresses.push(senderAcc.publicKey);
        // });

        // await sent.wait();

        // return txAdd;
      });

      // console.log('txs.length', txs.length);
      // console.log('eligibleAddresses.length', eligibleAddresses.length);

      // await Promise.all(txs);

      // for (let i = 0; i < 10; i++) {
      //   let start = i * 5;
      //   let end = start + 4;

      //   const txAdd = await Mina.transaction(deployerAcc, () => {
      //     console.log('start', start);
      //     console.log('end', end);
      //     for (let j = start; j <= end; j++) {
      //       console.log('j', j);
      //       const senderAcc = senderAccounts[j].publicKey;
      //       const { address, witness } = initAddEligibleAddress(senderAcc);
      //       eligibleAddresses.push(senderAcc);
      //       zkApp.addEligibleAddress(address, witness);
      //     }
      //   });

      //   // txs.push(txAdd);

      //   await txAdd.prove();
      //   await txAdd.sign([deployerAccPrivKey, zkAppPrivKey]).send();

      //   console.log('eligibleAddresses.length', eligibleAddresses.length);
      // }

      // const readyTxs = await Promise.all(txs);

      // const plz = readyTxs.map((tx) => {
      //   return [tx.prove(), tx.sign([deployerAccPrivKey, zkAppPrivKey]).send()];
      // });

      // const results = await Promise.all(plz.flat());

      const appCommitment = zkApp.eligibleAddressesCommitment.get();

      appCommitment.assertEquals(eligibleAddressesTree.getRoot());

      // expect(appCommitment).toEqual(eligibleAddressesTree.getRoot());
      // )
      // .sign([deployerAccPrivKey, zkAppPrivKey])
      // .send();
      // }

      // const randomIndex = Math.floor(Math.random() * 10);
      // const senderAcc = senderAccounts[randomIndex].publicKey;
      // const { address } = initAddEligibleAddress(senderAcc);

      // const m = Field(32);
      // const { message, addressWitness, messageWitness } =
      //   await initDepositMessage(senderAcc, m);

      // const tx = await Mina.transaction(deployerAcc, () => {
      //   zkApp.depositMessage(address, message, addressWitness, messageWitness);
      // });

      // await tx.sign([deployerAccPrivKey, zkAppPrivKey]).send();

      // expect(tx).resolves;
    });

    // describe('Fail Cases', () => {
    //   let senderAcc: PublicKey;

    //   beforeEach(async () => {
    //     await localDeploy();
    //     senderAcc = senderAccounts[0].publicKey;
    //   });

    //   it('should be able to add a user to registered addresses', async () => {
    //     await localDeploy();

    //     await addEligibleAddress(senderAcc);
    //   });

    //   it('should be able to deposit a message which passes all tests', async () => {
    //     const validMessage = Field(32); // 0b100000

    //     await initAddEligibleAddress(senderAcc);

    //     zkApp.eligibleAddressesCommitment
    //       .get()
    //       .assertEquals(eligibleAddressesTree.getRoot());

    //     const { address, message, addressWitness, messageWitness } =
    //       await initDepositMessage(senderAcc, validMessage);

    //     // let tx: Mina.Transaction;

    //     expect(async () => {
    //       await Mina.transaction(deployerAcc, () => {
    //         zkApp.depositMessage(
    //           address,
    //           message,
    //           addressWitness,
    //           messageWitness
    //         );
    //       });
    //     }).resolves;

    //     // if the transaction was successful, we can update our off-chain storage as well
    //     messages.set(senderAcc, message.hash());

    //     const messagesLeafCount = BigInt(messages.size);

    //     messageTree.setLeaf(messagesLeafCount, message.hash());

    //     zkApp.messagesCommitment.get().assertEquals(messageTree.getRoot());
    //   });

    //   it('Checks that if flag 1 is true, then all other flags must be false', async () => {
    //     // await localDeploy();
    //     const validMessage = Field(33); // 0b100001

    //     await addEligibleAddress(senderAcc);

    //     zkApp.eligibleAddressesCommitment
    //       .get()
    //       .assertEquals(eligibleAddressesTree.getRoot());

    //     await depositMessage(senderAcc, validMessage);

    //     zkApp.messagesCommitment.get().assertEquals(messageTree.getRoot());
    //   });

    //   it('Checks that if flag 2 is true, then flag 3 must also be true.', async () => {
    //     await localDeploy();
    //   });

    //   it('Checks that if flag 4 is true, then flags 5 and 6 must be false.', async () => {
    //     await localDeploy();
    //   });

    //   it('', async () => {
    //     await localDeploy();
    //   });
    // });
  });
});

// await depositMessage(Local.testAccounts[1].publicKey, Field(32)); // 0b100000 - Passes all tests
// await depositMessage(Local.testAccounts[1].publicKey, Field(33)); // 0b100001 - Fails test 1
// await depositMessage(Local.testAccounts[1].publicKey, Field(16)); // 0b010000 - Fails test 2
// await depositMessage(Local.testAccounts[1].publicKey, Field(5)); // 0b000101 - Fails test 3
//
// it('throws an error if the NFT ID and endorser Hash are correct but the provided signature is invalid', async () => {
//   const zkAppInstance = new Cpone(zkAppAddress);
//   await localDeploy(zkAppInstance, zkAppPrivateKey, deployerAccount);

//   const incorrectNftHash = Poseidon.hash([Field(123)]);
//   const signature = Signature.create(privKey, [
//     incorrectNftHash,
//     endorserHash,
//   ]);

//   expect(async () => {
//     await Mina.transaction(deployerAccount, () => {
//       zkAppInstance.verify(
//         nftHash,
//         endorserHash,
//         signature ?? fail('something is wrong with the signature')
//       );
//     });
//   }).rejects;
// });
