/* Static GPIO model/configuration state (ADR-0002).
 *
 * The qemu target uses this as its GPIO hardware model. TARGET_C6 also keeps
 * it as a lightweight software configuration guard so gpio_write/read can
 * reject unconfigured pins deterministically.
 */

        .section .bss.gpio_model, "aw", @nobits
        .balign 4
        .global gpio_model_configured
        .type   gpio_model_configured, @object
gpio_model_configured:
        .skip   4
        .size   gpio_model_configured, 4

        .global gpio_model_direction
        .type   gpio_model_direction, @object
gpio_model_direction:
        .skip   4
        .size   gpio_model_direction, 4

        .global gpio_model_level
        .type   gpio_model_level, @object
gpio_model_level:
        .skip   4
        .size   gpio_model_level, 4
