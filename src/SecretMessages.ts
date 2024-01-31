import {
  SmartContract,
  Poseidon,
  Field,
  State,
  state,
  PublicKey,
  method,
  MerkleWitness,
  Struct,
  Bool,
  Provable,
  Nullifier,
  MerkleMapWitness,
  MerkleMap,
} from 'o1js';

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
  @state(Field) nullifierRoot = State<Field>();
  @state(Field) nullifierMessage = State<Field>();

  events = {
    MessageDeposited: Field,
  };

  @method addEligibleAddress(
    address: Address,
    path: ElligibleAddressMerkleWitness
  ) {
    // Validate that there is room for another address (i.e. there are less than 100 addresses)
    const count = path.calculateIndex();
    count.assertLessThan(Field(100));

    let newCommitment = path.calculateRoot(address.hash());
    this.eligibleAddressesCommitment.set(newCommitment);
  }

  @method depositMessage(
    address: Address,
    message: Message,
    eligibleAddressPath: ElligibleAddressMerkleWitness,
    messagePath: MessageMerkleWitness,
    nullifier: Nullifier
  ) {
    let nullifierRoot = this.nullifierRoot.getAndRequireEquals();
    let nullifierMessage = this.nullifierMessage.getAndRequireEquals();
    // verify the nullifier
    nullifier.verify([nullifierMessage]);

    let nullifierWitness = Provable.witness(MerkleMapWitness, () =>
      NullifierTree.getWitness(nullifier.key())
    );

    // we compute the current root and make sure the entry is set to 0 (= unused)
    nullifier.assertUnused(nullifierWitness, nullifierRoot);

    // we set the nullifier to 1 (= used) and calculate the new root
    let newRoot = nullifier.setUsed(nullifierWitness);

    // we update the on-chain root
    this.nullifierRoot.set(newRoot);

    // we fetch the on-chain commitment for the Eligible Addresses Merkle Tree
    const commitment = this.eligibleAddressesCommitment.getAndRequireEquals();

    // we check that the address is within the committed Eligible Addresses Merkle Tree
    eligibleAddressPath
      .calculateRoot(address.hash())
      .assertEquals(
        commitment,
        'address is not in the committed Eligible Addresses Merkle Tree'
      );

    // Enforce flag rules
    const flags: Bool[] = message.data.toBits().slice(0, 6).reverse();
    const f1 = flags[0];
    const f2 = flags[1];
    const f3 = flags[2];
    const f4 = flags[3];
    const f5 = flags[4];
    const f6 = flags[5];

    // If flag 1 is true, then all other flags must be false
    Bool.or(
      f1.not(),
      Bool.and(
        f2.not(),
        Bool.and(f3.not(), Bool.and(f4.not(), Bool.and(f5.not(), f6.not())))
      )
    ).assertTrue('flag 1 is true, and all other flags are not false');

    // If flag 2 is true, then flag 3 must also be true.
    Bool.or(f2.not(), Bool.and(f2, f3)).assertTrue(
      'flag 2 is true, and flag 3 is not true'
    );

    // If flag 4 is true, then flags 5 and 6 must be false.
    Bool.or(f4.not(), Bool.and(f5.not(), f6.not())).assertTrue(
      'flag 4 is true, and either flag 5 and 6 are not false'
    );

    // we calculate the new Merkle Root and set it
    let newCommitment = messagePath.calculateRoot(message.hash());
    this.messagesCommitment.set(newCommitment);

    // Emits a MessageDeposited event
    this.emitEvent('MessageDeposited', message.data);
    // this.emitEvent('MessageDeposited', message.hash());
  }
}

export const NullifierTree = new MerkleMap();
