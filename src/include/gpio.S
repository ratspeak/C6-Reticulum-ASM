/* GPIO helper constants for milestone-8 LoRa wiring. */

        .equ GPIO_OK,                   0
        .equ GPIO_ERR_INVAL,           -1

        /* The public helpers are deliberately scoped to the four SX1262
         * control/IRQ pins selected in docs/hardware/lora.md. */
        .equ GPIO_PIN_LIMIT,            31
        .equ GPIO_LORA_NSS_PIN,         0
        .equ GPIO_LORA_DIO1_PIN,        5
        .equ GPIO_LORA_BUSY_PIN,        6
        .equ GPIO_LORA_NRST_PIN,        7
        .equ GPIO_LORA_OUTPUT_MASK,     0x00000081
        .equ GPIO_LORA_INPUT_MASK,      0x00000060
        .equ GPIO_LORA_ALLOWED_MASK,    0x000000e1

        /* ESP32-C6 register addresses sourced from ESP-IDF v6.0
         * components/soc/esp32c6/{include,register}/soc headers. */
        .equ C6_GPIO_BASE,              0x60091000
        .equ C6_GPIO_OUT_W1TS,          C6_GPIO_BASE + 0x08
        .equ C6_GPIO_OUT_W1TC,          C6_GPIO_BASE + 0x0c
        .equ C6_GPIO_ENABLE_W1TS,       C6_GPIO_BASE + 0x24
        .equ C6_GPIO_ENABLE_W1TC,       C6_GPIO_BASE + 0x28
        .equ C6_GPIO_IN,                C6_GPIO_BASE + 0x3c
        .equ C6_GPIO_FUNC_OUT_SEL_BASE, C6_GPIO_BASE + 0x554

        .equ C6_IO_MUX_BASE,            0x60090000
        .equ C6_IO_MUX_GPIO0,           C6_IO_MUX_BASE + 0x04
        .equ C6_IO_MUX_CLEAR_MASK,      0xffff8c7f
        .equ C6_IO_MUX_GPIO_FUNC,       0x00001000
        .equ C6_IO_MUX_GPIO_FUNC_IE,    0x00001200
        .equ C6_SIG_GPIO_OUT_IDX,       128
