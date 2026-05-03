/* Static announce builder scratch (ADR-0002).
 *
 * announce_build assembles signed data here before invoking ed25519_sign.
 * The buffers are not reentrant; milestone-3 has a single-threaded builder
 * path and no interrupt caller for announces.
 */

        .include "announce.S"
        .include "destination.S"

        .section .bss.announce_scratch, "aw", @nobits

        .global announce_destination_hash
        .type   announce_destination_hash, @object
        .balign 4
announce_destination_hash:
        .zero   DESTINATION_HASH_SIZE
        .size   announce_destination_hash, DESTINATION_HASH_SIZE

        .global announce_random_hash
        .type   announce_random_hash, @object
        .balign 4
announce_random_hash:
        .zero   ANNOUNCE_RANDOM_HASH_SIZE
        .size   announce_random_hash, ANNOUNCE_RANDOM_HASH_SIZE

        .global announce_signed_data
        .type   announce_signed_data, @object
        .balign 4
announce_signed_data:
        .zero   ANNOUNCE_SIGNED_DATA_MAX
        .size   announce_signed_data, ANNOUNCE_SIGNED_DATA_MAX

        .global announce_signature
        .type   announce_signature, @object
        .balign 4
announce_signature:
        .zero   ANNOUNCE_SIGNATURE_SIZE
        .size   announce_signature, ANNOUNCE_SIGNATURE_SIZE

