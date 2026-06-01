use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("LZMS compressed data is corrupt: {0}")]
    Corrupt(&'static str),
}

const NUM_MAIN_PROBS: usize = 16;
const NUM_MATCH_PROBS: usize = 32;
const NUM_LZ_PROBS: usize = 64;
const NUM_DELTA_PROBS: usize = 64;
const NUM_LZ_REP_PROBS: usize = 64;
const NUM_DELTA_REP_PROBS: usize = 64;
const NUM_LZ_REP_DECISIONS: usize = 2;
const NUM_DELTA_REP_DECISIONS: usize = 2;
const NUM_LZ_REPS: usize = 3;
const NUM_DELTA_REPS: usize = 3;

const PROBABILITY_BITS: u32 = 6;
const PROBABILITY_DENOMINATOR: u32 = 64;
const INITIAL_PROBABILITY: u32 = 48;
const INITIAL_RECENT_BITS: u64 = 0x0000000055555555;

const LITERAL_REBUILD: usize = 1024;
const LZ_OFFSET_REBUILD: usize = 1024;
const LENGTH_REBUILD: usize = 512;
const DELTA_OFFSET_REBUILD: usize = 1024;
const DELTA_POWER_REBUILD: usize = 512;

const NUM_LENGTH_SYMS: usize = 54;
const NUM_DELTA_POWER_SYMS: usize = 8;
const MAX_OFFSET_SYMS: usize = 799;
const MAX_CODEWORD_LEN: u8 = 15;

const X86_ID_WINDOW: i32 = 65535;
const X86_MAX_TRANS_OFFSET: i32 = 1023;

const OFFSET_SLOT_BASE: [u32; MAX_OFFSET_SYMS + 1] = [
    0x00000001, 0x00000002, 0x00000003, 0x00000004, 0x00000005, 0x00000006, 0x00000007, 0x00000008,
    0x00000009, 0x0000000d, 0x00000011, 0x00000015, 0x00000019, 0x0000001d, 0x00000021, 0x00000025,
    0x00000029, 0x0000002d, 0x00000035, 0x0000003d, 0x00000045, 0x0000004d, 0x00000055, 0x0000005d,
    0x00000065, 0x00000075, 0x00000085, 0x00000095, 0x000000a5, 0x000000b5, 0x000000c5, 0x000000d5,
    0x000000e5, 0x000000f5, 0x00000105, 0x00000125, 0x00000145, 0x00000165, 0x00000185, 0x000001a5,
    0x000001c5, 0x000001e5, 0x00000205, 0x00000225, 0x00000245, 0x00000265, 0x00000285, 0x000002a5,
    0x000002c5, 0x000002e5, 0x00000325, 0x00000365, 0x000003a5, 0x000003e5, 0x00000425, 0x00000465,
    0x000004a5, 0x000004e5, 0x00000525, 0x00000565, 0x000005a5, 0x000005e5, 0x00000625, 0x00000665,
    0x000006a5, 0x00000725, 0x000007a5, 0x00000825, 0x000008a5, 0x00000925, 0x000009a5, 0x00000a25,
    0x00000aa5, 0x00000b25, 0x00000ba5, 0x00000c25, 0x00000ca5, 0x00000d25, 0x00000da5, 0x00000e25,
    0x00000ea5, 0x00000f25, 0x00000fa5, 0x00001025, 0x000010a5, 0x000011a5, 0x000012a5, 0x000013a5,
    0x000014a5, 0x000015a5, 0x000016a5, 0x000017a5, 0x000018a5, 0x000019a5, 0x00001aa5, 0x00001ba5,
    0x00001ca5, 0x00001da5, 0x00001ea5, 0x00001fa5, 0x000020a5, 0x000021a5, 0x000022a5, 0x000023a5,
    0x000024a5, 0x000026a5, 0x000028a5, 0x00002aa5, 0x00002ca5, 0x00002ea5, 0x000030a5, 0x000032a5,
    0x000034a5, 0x000036a5, 0x000038a5, 0x00003aa5, 0x00003ca5, 0x00003ea5, 0x000040a5, 0x000042a5,
    0x000044a5, 0x000046a5, 0x000048a5, 0x00004aa5, 0x00004ca5, 0x00004ea5, 0x000050a5, 0x000052a5,
    0x000054a5, 0x000056a5, 0x000058a5, 0x00005aa5, 0x00005ca5, 0x00005ea5, 0x000060a5, 0x000064a5,
    0x000068a5, 0x00006ca5, 0x000070a5, 0x000074a5, 0x000078a5, 0x00007ca5, 0x000080a5, 0x000084a5,
    0x000088a5, 0x00008ca5, 0x000090a5, 0x000094a5, 0x000098a5, 0x00009ca5, 0x0000a0a5, 0x0000a4a5,
    0x0000a8a5, 0x0000aca5, 0x0000b0a5, 0x0000b4a5, 0x0000b8a5, 0x0000bca5, 0x0000c0a5, 0x0000c4a5,
    0x0000c8a5, 0x0000cca5, 0x0000d0a5, 0x0000d4a5, 0x0000d8a5, 0x0000dca5, 0x0000e0a5, 0x0000e4a5,
    0x0000eca5, 0x0000f4a5, 0x0000fca5, 0x000104a5, 0x00010ca5, 0x000114a5, 0x00011ca5, 0x000124a5,
    0x00012ca5, 0x000134a5, 0x00013ca5, 0x000144a5, 0x00014ca5, 0x000154a5, 0x00015ca5, 0x000164a5,
    0x00016ca5, 0x000174a5, 0x00017ca5, 0x000184a5, 0x00018ca5, 0x000194a5, 0x00019ca5, 0x0001a4a5,
    0x0001aca5, 0x0001b4a5, 0x0001bca5, 0x0001c4a5, 0x0001cca5, 0x0001d4a5, 0x0001dca5, 0x0001e4a5,
    0x0001eca5, 0x0001f4a5, 0x0001fca5, 0x000204a5, 0x00020ca5, 0x000214a5, 0x00021ca5, 0x000224a5,
    0x000234a5, 0x000244a5, 0x000254a5, 0x000264a5, 0x000274a5, 0x000284a5, 0x000294a5, 0x0002a4a5,
    0x0002b4a5, 0x0002c4a5, 0x0002d4a5, 0x0002e4a5, 0x0002f4a5, 0x000304a5, 0x000314a5, 0x000324a5,
    0x000334a5, 0x000344a5, 0x000354a5, 0x000364a5, 0x000374a5, 0x000384a5, 0x000394a5, 0x0003a4a5,
    0x0003b4a5, 0x0003c4a5, 0x0003d4a5, 0x0003e4a5, 0x0003f4a5, 0x000404a5, 0x000414a5, 0x000424a5,
    0x000434a5, 0x000444a5, 0x000454a5, 0x000464a5, 0x000474a5, 0x000484a5, 0x000494a5, 0x0004a4a5,
    0x0004b4a5, 0x0004c4a5, 0x0004e4a5, 0x000504a5, 0x000524a5, 0x000544a5, 0x000564a5, 0x000584a5,
    0x0005a4a5, 0x0005c4a5, 0x0005e4a5, 0x000604a5, 0x000624a5, 0x000644a5, 0x000664a5, 0x000684a5,
    0x0006a4a5, 0x0006c4a5, 0x0006e4a5, 0x000704a5, 0x000724a5, 0x000744a5, 0x000764a5, 0x000784a5,
    0x0007a4a5, 0x0007c4a5, 0x0007e4a5, 0x000804a5, 0x000824a5, 0x000844a5, 0x000864a5, 0x000884a5,
    0x0008a4a5, 0x0008c4a5, 0x0008e4a5, 0x000904a5, 0x000924a5, 0x000944a5, 0x000964a5, 0x000984a5,
    0x0009a4a5, 0x0009c4a5, 0x0009e4a5, 0x000a04a5, 0x000a24a5, 0x000a44a5, 0x000a64a5, 0x000aa4a5,
    0x000ae4a5, 0x000b24a5, 0x000b64a5, 0x000ba4a5, 0x000be4a5, 0x000c24a5, 0x000c64a5, 0x000ca4a5,
    0x000ce4a5, 0x000d24a5, 0x000d64a5, 0x000da4a5, 0x000de4a5, 0x000e24a5, 0x000e64a5, 0x000ea4a5,
    0x000ee4a5, 0x000f24a5, 0x000f64a5, 0x000fa4a5, 0x000fe4a5, 0x001024a5, 0x001064a5, 0x0010a4a5,
    0x0010e4a5, 0x001124a5, 0x001164a5, 0x0011a4a5, 0x0011e4a5, 0x001224a5, 0x001264a5, 0x0012a4a5,
    0x0012e4a5, 0x001324a5, 0x001364a5, 0x0013a4a5, 0x0013e4a5, 0x001424a5, 0x001464a5, 0x0014a4a5,
    0x0014e4a5, 0x001524a5, 0x001564a5, 0x0015a4a5, 0x0015e4a5, 0x001624a5, 0x001664a5, 0x0016a4a5,
    0x0016e4a5, 0x001724a5, 0x001764a5, 0x0017a4a5, 0x0017e4a5, 0x001824a5, 0x001864a5, 0x0018a4a5,
    0x0018e4a5, 0x001924a5, 0x001964a5, 0x0019e4a5, 0x001a64a5, 0x001ae4a5, 0x001b64a5, 0x001be4a5,
    0x001c64a5, 0x001ce4a5, 0x001d64a5, 0x001de4a5, 0x001e64a5, 0x001ee4a5, 0x001f64a5, 0x001fe4a5,
    0x002064a5, 0x0020e4a5, 0x002164a5, 0x0021e4a5, 0x002264a5, 0x0022e4a5, 0x002364a5, 0x0023e4a5,
    0x002464a5, 0x0024e4a5, 0x002564a5, 0x0025e4a5, 0x002664a5, 0x0026e4a5, 0x002764a5, 0x0027e4a5,
    0x002864a5, 0x0028e4a5, 0x002964a5, 0x0029e4a5, 0x002a64a5, 0x002ae4a5, 0x002b64a5, 0x002be4a5,
    0x002c64a5, 0x002ce4a5, 0x002d64a5, 0x002de4a5, 0x002e64a5, 0x002ee4a5, 0x002f64a5, 0x002fe4a5,
    0x003064a5, 0x0030e4a5, 0x003164a5, 0x0031e4a5, 0x003264a5, 0x0032e4a5, 0x003364a5, 0x0033e4a5,
    0x003464a5, 0x0034e4a5, 0x003564a5, 0x0035e4a5, 0x003664a5, 0x0036e4a5, 0x003764a5, 0x0037e4a5,
    0x003864a5, 0x0038e4a5, 0x003964a5, 0x0039e4a5, 0x003a64a5, 0x003ae4a5, 0x003b64a5, 0x003be4a5,
    0x003c64a5, 0x003ce4a5, 0x003d64a5, 0x003de4a5, 0x003ee4a5, 0x003fe4a5, 0x0040e4a5, 0x0041e4a5,
    0x0042e4a5, 0x0043e4a5, 0x0044e4a5, 0x0045e4a5, 0x0046e4a5, 0x0047e4a5, 0x0048e4a5, 0x0049e4a5,
    0x004ae4a5, 0x004be4a5, 0x004ce4a5, 0x004de4a5, 0x004ee4a5, 0x004fe4a5, 0x0050e4a5, 0x0051e4a5,
    0x0052e4a5, 0x0053e4a5, 0x0054e4a5, 0x0055e4a5, 0x0056e4a5, 0x0057e4a5, 0x0058e4a5, 0x0059e4a5,
    0x005ae4a5, 0x005be4a5, 0x005ce4a5, 0x005de4a5, 0x005ee4a5, 0x005fe4a5, 0x0060e4a5, 0x0061e4a5,
    0x0062e4a5, 0x0063e4a5, 0x0064e4a5, 0x0065e4a5, 0x0066e4a5, 0x0067e4a5, 0x0068e4a5, 0x0069e4a5,
    0x006ae4a5, 0x006be4a5, 0x006ce4a5, 0x006de4a5, 0x006ee4a5, 0x006fe4a5, 0x0070e4a5, 0x0071e4a5,
    0x0072e4a5, 0x0073e4a5, 0x0074e4a5, 0x0075e4a5, 0x0076e4a5, 0x0077e4a5, 0x0078e4a5, 0x0079e4a5,
    0x007ae4a5, 0x007be4a5, 0x007ce4a5, 0x007de4a5, 0x007ee4a5, 0x007fe4a5, 0x0080e4a5, 0x0081e4a5,
    0x0082e4a5, 0x0083e4a5, 0x0084e4a5, 0x0085e4a5, 0x0086e4a5, 0x0087e4a5, 0x0088e4a5, 0x0089e4a5,
    0x008ae4a5, 0x008be4a5, 0x008ce4a5, 0x008de4a5, 0x008fe4a5, 0x0091e4a5, 0x0093e4a5, 0x0095e4a5,
    0x0097e4a5, 0x0099e4a5, 0x009be4a5, 0x009de4a5, 0x009fe4a5, 0x00a1e4a5, 0x00a3e4a5, 0x00a5e4a5,
    0x00a7e4a5, 0x00a9e4a5, 0x00abe4a5, 0x00ade4a5, 0x00afe4a5, 0x00b1e4a5, 0x00b3e4a5, 0x00b5e4a5,
    0x00b7e4a5, 0x00b9e4a5, 0x00bbe4a5, 0x00bde4a5, 0x00bfe4a5, 0x00c1e4a5, 0x00c3e4a5, 0x00c5e4a5,
    0x00c7e4a5, 0x00c9e4a5, 0x00cbe4a5, 0x00cde4a5, 0x00cfe4a5, 0x00d1e4a5, 0x00d3e4a5, 0x00d5e4a5,
    0x00d7e4a5, 0x00d9e4a5, 0x00dbe4a5, 0x00dde4a5, 0x00dfe4a5, 0x00e1e4a5, 0x00e3e4a5, 0x00e5e4a5,
    0x00e7e4a5, 0x00e9e4a5, 0x00ebe4a5, 0x00ede4a5, 0x00efe4a5, 0x00f1e4a5, 0x00f3e4a5, 0x00f5e4a5,
    0x00f7e4a5, 0x00f9e4a5, 0x00fbe4a5, 0x00fde4a5, 0x00ffe4a5, 0x0101e4a5, 0x0103e4a5, 0x0105e4a5,
    0x0107e4a5, 0x0109e4a5, 0x010be4a5, 0x010de4a5, 0x010fe4a5, 0x0111e4a5, 0x0113e4a5, 0x0115e4a5,
    0x0117e4a5, 0x0119e4a5, 0x011be4a5, 0x011de4a5, 0x011fe4a5, 0x0121e4a5, 0x0123e4a5, 0x0125e4a5,
    0x0127e4a5, 0x0129e4a5, 0x012be4a5, 0x012de4a5, 0x012fe4a5, 0x0131e4a5, 0x0133e4a5, 0x0135e4a5,
    0x0137e4a5, 0x013be4a5, 0x013fe4a5, 0x0143e4a5, 0x0147e4a5, 0x014be4a5, 0x014fe4a5, 0x0153e4a5,
    0x0157e4a5, 0x015be4a5, 0x015fe4a5, 0x0163e4a5, 0x0167e4a5, 0x016be4a5, 0x016fe4a5, 0x0173e4a5,
    0x0177e4a5, 0x017be4a5, 0x017fe4a5, 0x0183e4a5, 0x0187e4a5, 0x018be4a5, 0x018fe4a5, 0x0193e4a5,
    0x0197e4a5, 0x019be4a5, 0x019fe4a5, 0x01a3e4a5, 0x01a7e4a5, 0x01abe4a5, 0x01afe4a5, 0x01b3e4a5,
    0x01b7e4a5, 0x01bbe4a5, 0x01bfe4a5, 0x01c3e4a5, 0x01c7e4a5, 0x01cbe4a5, 0x01cfe4a5, 0x01d3e4a5,
    0x01d7e4a5, 0x01dbe4a5, 0x01dfe4a5, 0x01e3e4a5, 0x01e7e4a5, 0x01ebe4a5, 0x01efe4a5, 0x01f3e4a5,
    0x01f7e4a5, 0x01fbe4a5, 0x01ffe4a5, 0x0203e4a5, 0x0207e4a5, 0x020be4a5, 0x020fe4a5, 0x0213e4a5,
    0x0217e4a5, 0x021be4a5, 0x021fe4a5, 0x0223e4a5, 0x0227e4a5, 0x022be4a5, 0x022fe4a5, 0x0233e4a5,
    0x0237e4a5, 0x023be4a5, 0x023fe4a5, 0x0243e4a5, 0x0247e4a5, 0x024be4a5, 0x024fe4a5, 0x0253e4a5,
    0x0257e4a5, 0x025be4a5, 0x025fe4a5, 0x0263e4a5, 0x0267e4a5, 0x026be4a5, 0x026fe4a5, 0x0273e4a5,
    0x0277e4a5, 0x027be4a5, 0x027fe4a5, 0x0283e4a5, 0x0287e4a5, 0x028be4a5, 0x028fe4a5, 0x0293e4a5,
    0x0297e4a5, 0x029be4a5, 0x029fe4a5, 0x02a3e4a5, 0x02a7e4a5, 0x02abe4a5, 0x02afe4a5, 0x02b3e4a5,
    0x02bbe4a5, 0x02c3e4a5, 0x02cbe4a5, 0x02d3e4a5, 0x02dbe4a5, 0x02e3e4a5, 0x02ebe4a5, 0x02f3e4a5,
    0x02fbe4a5, 0x0303e4a5, 0x030be4a5, 0x0313e4a5, 0x031be4a5, 0x0323e4a5, 0x032be4a5, 0x0333e4a5,
    0x033be4a5, 0x0343e4a5, 0x034be4a5, 0x0353e4a5, 0x035be4a5, 0x0363e4a5, 0x036be4a5, 0x0373e4a5,
    0x037be4a5, 0x0383e4a5, 0x038be4a5, 0x0393e4a5, 0x039be4a5, 0x03a3e4a5, 0x03abe4a5, 0x03b3e4a5,
    0x03bbe4a5, 0x03c3e4a5, 0x03cbe4a5, 0x03d3e4a5, 0x03dbe4a5, 0x03e3e4a5, 0x03ebe4a5, 0x03f3e4a5,
    0x03fbe4a5, 0x0403e4a5, 0x040be4a5, 0x0413e4a5, 0x041be4a5, 0x0423e4a5, 0x042be4a5, 0x0433e4a5,
    0x043be4a5, 0x0443e4a5, 0x044be4a5, 0x0453e4a5, 0x045be4a5, 0x0463e4a5, 0x046be4a5, 0x0473e4a5,
    0x047be4a5, 0x0483e4a5, 0x048be4a5, 0x0493e4a5, 0x049be4a5, 0x04a3e4a5, 0x04abe4a5, 0x04b3e4a5,
    0x04bbe4a5, 0x04c3e4a5, 0x04cbe4a5, 0x04d3e4a5, 0x04dbe4a5, 0x04e3e4a5, 0x04ebe4a5, 0x04f3e4a5,
    0x04fbe4a5, 0x0503e4a5, 0x050be4a5, 0x0513e4a5, 0x051be4a5, 0x0523e4a5, 0x052be4a5, 0x0533e4a5,
    0x053be4a5, 0x0543e4a5, 0x054be4a5, 0x0553e4a5, 0x055be4a5, 0x0563e4a5, 0x056be4a5, 0x0573e4a5,
    0x057be4a5, 0x0583e4a5, 0x058be4a5, 0x0593e4a5, 0x059be4a5, 0x05a3e4a5, 0x05abe4a5, 0x05b3e4a5,
    0x05bbe4a5, 0x05c3e4a5, 0x05cbe4a5, 0x05d3e4a5, 0x05dbe4a5, 0x05e3e4a5, 0x05ebe4a5, 0x05f3e4a5,
    0x05fbe4a5, 0x060be4a5, 0x061be4a5, 0x062be4a5, 0x063be4a5, 0x064be4a5, 0x065be4a5, 0x465be4a5,
];

const EXTRA_OFFSET_BITS: [u8; MAX_OFFSET_SYMS] = [
    0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 9, 9, 9, 9, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    11, 11, 11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 17, 17,
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
    17, 17, 17, 17, 17, 17, 17, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 20, 20, 20, 20, 20, 20, 30,
];

const LENGTH_SLOT_BASE: [u32; NUM_LENGTH_SYMS + 1] = [
    0x00000001, 0x00000002, 0x00000003, 0x00000004, 0x00000005, 0x00000006, 0x00000007, 0x00000008,
    0x00000009, 0x0000000a, 0x0000000b, 0x0000000c, 0x0000000d, 0x0000000e, 0x0000000f, 0x00000010,
    0x00000011, 0x00000012, 0x00000013, 0x00000014, 0x00000015, 0x00000016, 0x00000017, 0x00000018,
    0x00000019, 0x0000001a, 0x0000001b, 0x0000001d, 0x0000001f, 0x00000021, 0x00000023, 0x00000027,
    0x0000002b, 0x0000002f, 0x00000033, 0x00000037, 0x0000003b, 0x00000043, 0x0000004b, 0x00000053,
    0x0000005b, 0x0000006b, 0x0000007b, 0x0000008b, 0x0000009b, 0x000000ab, 0x000000cb, 0x000000eb,
    0x0000012b, 0x000001ab, 0x000002ab, 0x000004ab, 0x000008ab, 0x000108ab, 0x400108ab,
];

const EXTRA_LENGTH_BITS: [u8; NUM_LENGTH_SYMS] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2,
    2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 5, 5, 6, 7, 8, 9, 10, 16, 30,
];

#[derive(Clone, Copy)]
struct ProbEntry {
    num_zero_bits: u32,
    recent_bits: u64,
}

impl ProbEntry {
    fn new() -> Self {
        Self {
            num_zero_bits: INITIAL_PROBABILITY,
            recent_bits: INITIAL_RECENT_BITS,
        }
    }

    fn probability(&self) -> u32 {
        let mut prob = self.num_zero_bits;

        prob = prob.wrapping_add((prob.wrapping_sub(1)) >> 31);
        prob = prob.wrapping_sub(prob >> PROBABILITY_BITS);
        prob
    }

    fn update(&mut self, bit: u32) {
        let evicted = (self.recent_bits >> (PROBABILITY_DENOMINATOR - 1)) as u32;
        self.num_zero_bits = self.num_zero_bits.wrapping_add(evicted).wrapping_sub(bit);
        self.recent_bits = (self.recent_bits << 1) | bit as u64;
    }
}

struct RangeDecoder<'a> {
    src: &'a [u8],
    pos: usize,
    range: u32,
    code: u32,
}

impl<'a> RangeDecoder<'a> {
    fn new(src: &'a [u8]) -> Result<Self, Error> {
        if src.len() < 4 {
            return Err(Error::Corrupt("compressed data too short"));
        }

        let hi = u16::from_le_bytes([src[0], src[1]]) as u32;
        let lo = u16::from_le_bytes([src[2], src[3]]) as u32;
        Ok(Self {
            src,
            pos: 4,
            range: 0xFFFF_FFFF,
            code: (hi << 16) | lo,
        })
    }

    fn decode_bit(&mut self, entry: &mut ProbEntry) -> u32 {
        let prob = entry.probability();

        if self.range & 0xFFFF_0000 == 0 {
            self.range <<= 16;
            let word = if self.pos + 1 < self.src.len() {
                u16::from_le_bytes([self.src[self.pos], self.src[self.pos + 1]]) as u32
            } else {
                0
            };
            self.code = (self.code << 16) | word;
            self.pos += 2;
        }
        let bound = (self.range >> PROBABILITY_BITS) * prob;
        let bit = if self.code < bound {
            self.range = bound;
            0u32
        } else {
            self.code -= bound;
            self.range -= bound;
            1u32
        };
        entry.update(bit);
        bit
    }
}

struct BackBits<'a> {
    src: &'a [u8],
    next: usize,
    bitbuf: u64,
    bitsleft: u32,
}

impl<'a> BackBits<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            next: src.len(),
            bitbuf: 0,
            bitsleft: 0,
        }
    }

    fn ensure(&mut self, n: u32) {
        while self.bitsleft < n {
            let avail = 64 - self.bitsleft;
            if self.next >= 2 {
                self.next -= 2;
                let word =
                    u16::from_le_bytes([self.src[self.next], self.src[self.next + 1]]) as u64;
                self.bitbuf |= word << (avail - 16);
                self.bitsleft += 16;
            } else {
                self.bitsleft += 16;
            }
        }
    }

    fn peek(&mut self, n: u32) -> u32 {
        self.ensure(n);

        (self.bitbuf >> (64 - n)) as u32
    }

    fn consume(&mut self, n: u32) {
        self.bitbuf <<= n;
        self.bitsleft -= n;
    }

    fn read(&mut self, n: u8) -> u32 {
        if n == 0 {
            return 0;
        }
        let v = self.peek(n as u32);
        self.consume(n as u32);
        v
    }
}

const TABLE_BITS: u32 = MAX_CODEWORD_LEN as u32;
const TABLE_SIZE: usize = 1 << TABLE_BITS;

struct Huffman {
    freqs: Vec<u32>,

    table: Vec<u32>,
    until_rebuild: usize,
    rebuild_freq: usize,
}

impl Huffman {
    fn new(num_syms: usize, rebuild_freq: usize) -> Self {
        let mut h = Self {
            freqs: vec![1u32; num_syms],
            table: vec![0u32; TABLE_SIZE],
            until_rebuild: rebuild_freq,
            rebuild_freq,
        };
        h.rebuild();
        h
    }

    fn rebuild(&mut self) {
        let n = self.freqs.len();
        let codelens = build_codelens(&self.freqs, MAX_CODEWORD_LEN);

        let mut count = [0u32; MAX_CODEWORD_LEN as usize + 1];
        for &cl in &codelens {
            if cl > 0 {
                count[cl as usize] += 1;
            }
        }
        let mut first = [0u32; MAX_CODEWORD_LEN as usize + 2];
        let mut c = 0u32;
        for bits in 1..=MAX_CODEWORD_LEN as usize {
            c <<= 1;
            first[bits] = c;
            c += count[bits];
        }
        let mut next = first;

        self.table.iter_mut().for_each(|e| *e = 0);
        for sym in 0..n {
            let cl = codelens[sym];
            if cl == 0 {
                continue;
            }
            let code = next[cl as usize];
            next[cl as usize] += 1;

            let fan = 1u32 << (TABLE_BITS - cl as u32);
            let base = code << (TABLE_BITS - cl as u32);
            let entry = ((sym as u32) << 8) | cl as u32;
            for j in 0..fan {
                self.table[(base + j) as usize] = entry;
            }
        }
    }

    fn decode(&mut self, bits: &mut BackBits<'_>) -> Result<usize, Error> {
        let prefix = bits.peek(TABLE_BITS) as usize;
        let entry = self.table[prefix];
        if entry == 0 {
            return Err(Error::Corrupt("huffman: invalid code"));
        }
        let cl = (entry & 0xFF) as u32;
        let s = (entry >> 8) as usize;
        bits.consume(cl);
        self.freqs[s] += 1;
        self.until_rebuild -= 1;
        if self.until_rebuild == 0 {
            self.rebuild();
            for f in &mut self.freqs {
                *f = (*f >> 1) + 1;
            }
            self.until_rebuild = self.rebuild_freq;
        }
        Ok(s)
    }
}

fn build_codelens(freqs: &[u32], max_bits: u8) -> Vec<u8> {
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;

    let n = freqs.len();
    let mut codelens = vec![0u8; n];
    let active: Vec<usize> = (0..n).filter(|&i| freqs[i] > 0).collect();
    if active.is_empty() {
        return codelens;
    }
    if active.len() == 1 {
        codelens[active[0]] = 1;
        return codelens;
    }

    let mut nodes: Vec<(u64, Option<usize>, Option<usize>)> = Vec::new();
    let mut heap: BinaryHeap<Reverse<(u64, usize)>> = BinaryHeap::new();
    for &sym in &active {
        let id = nodes.len();
        nodes.push((freqs[sym] as u64, None, None));
        heap.push(Reverse((freqs[sym] as u64, id)));
    }
    while heap.len() > 1 {
        let Reverse((f1, i1)) = heap.pop().unwrap();
        let Reverse((f2, i2)) = heap.pop().unwrap();
        let id = nodes.len();
        nodes.push((f1 + f2, Some(i1), Some(i2)));
        heap.push(Reverse((f1 + f2, id)));
    }

    fn assign(
        nodes: &[(u64, Option<usize>, Option<usize>)],
        active: &[usize],
        idx: usize,
        depth: u8,
        codelens: &mut Vec<u8>,
        max: u8,
    ) {
        match (nodes[idx].1, nodes[idx].2) {
            (None, None) => {
                if idx < active.len() {
                    codelens[active[idx]] = depth.min(max).max(1);
                }
            }
            (Some(l), Some(r)) => {
                assign(nodes, active, l, depth + 1, codelens, max);
                assign(nodes, active, r, depth + 1, codelens, max);
            }
            _ => {}
        }
    }
    if let Some(root) = nodes.len().checked_sub(1) {
        assign(&nodes, &active, root, 0, &mut codelens, max_bits);
    }
    codelens
}

fn num_offset_slots(uncompressed_size: usize) -> usize {
    if uncompressed_size < 2 {
        return 0;
    }

    let val = (uncompressed_size - 1) as u32;
    let mut l = 0usize;
    let mut r = MAX_OFFSET_SYMS - 1;
    loop {
        let mid = (l + r) / 2;
        if val >= OFFSET_SLOT_BASE[mid] {
            if val < OFFSET_SLOT_BASE[mid + 1] {
                return mid + 1;
            }
            l = mid + 1;
        } else {
            r = mid - 1;
        }
    }
}

fn x86_filter_undo(data: &mut [u8]) {
    let size = data.len() as i32;
    if size <= 17 {
        return;
    }

    let mut last_target_usages = vec![-X86_ID_WINDOW - 1i32; 65536];
    let mut last_x86_pos: i32 = -(X86_MAX_TRANS_OFFSET + 1);
    let mut p: i32 = 1;

    while p < size - 16 {
        let b = data[p as usize];
        if b != 0x48 && b != 0x4C && b != 0xE8 && b != 0xE9 && b != 0xF0 && b != 0xFF {
            p += 1;
            continue;
        }

        let (opcode_nbytes, max_trans): (i32, i32) = match b {
            0xF0 => {
                if p + 2 < size && data[(p + 1) as usize] == 0x83 && data[(p + 2) as usize] == 0x05
                {
                    (3, X86_MAX_TRANS_OFFSET)
                } else {
                    p += 1;
                    continue;
                }
            }
            0xFF => {
                if p + 1 < size && data[(p + 1) as usize] == 0x15 {
                    (2, X86_MAX_TRANS_OFFSET)
                } else {
                    p += 1;
                    continue;
                }
            }
            0xE8 => (1, X86_MAX_TRANS_OFFSET / 2),
            0xE9 => {
                p += 5;
                continue;
            }
            0x48 | 0x4C => {
                if p + 2 < size && (data[(p + 2) as usize] & 0x07) == 0x05 {
                    let op = data[(p + 1) as usize];
                    if op == 0x8D
                        || (op == 0x8B && (b & 0x04 == 0) && (data[(p + 2) as usize] & 0xF0 == 0))
                    {
                        (3, X86_MAX_TRANS_OFFSET)
                    } else {
                        p += 1;
                        continue;
                    }
                } else {
                    p += 1;
                    continue;
                }
            }
            _ => {
                p += 1;
                continue;
            }
        };

        let i = p;
        p += opcode_nbytes;

        if p + 4 > size {
            break;
        }

        let target16 = (i as u32)
            .wrapping_add(u16::from_le_bytes([data[p as usize], data[(p + 1) as usize]]) as u32)
            as u16;

        if i - last_x86_pos <= max_trans {
            let n = u32::from_le_bytes([
                data[p as usize],
                data[(p + 1) as usize],
                data[(p + 2) as usize],
                data[(p + 3) as usize],
            ]);
            let restored = n.wrapping_sub(i as u32);
            let bytes = restored.to_le_bytes();
            data[p as usize] = bytes[0];
            data[(p + 1) as usize] = bytes[1];
            data[(p + 2) as usize] = bytes[2];
            data[(p + 3) as usize] = bytes[3];
        }

        let target_idx = target16 as usize;
        if i - last_target_usages[target_idx] <= X86_ID_WINDOW_SIZE as i32 {
            last_x86_pos = i + opcode_nbytes + 3;
        }
        last_target_usages[target_idx] = i + opcode_nbytes + 3;

        p += 4;
    }
}

const X86_ID_WINDOW_SIZE: i32 = X86_ID_WINDOW;

pub fn decompress(src: &[u8], uncompressed_size: usize) -> Result<Vec<u8>, Error> {
    if src.len() < 4 || src.len() & 1 != 0 {
        return Err(Error::Corrupt("compressed data invalid size"));
    }
    if uncompressed_size == 0 {
        return Ok(vec![]);
    }

    let num_slots = num_offset_slots(uncompressed_size);

    let mut out = vec![0u8; uncompressed_size];
    let mut out_pos = 0usize;

    let mut rd = RangeDecoder::new(src)?;
    let mut bits = BackBits::new(src);

    let mut main_probs = [ProbEntry::new(); NUM_MAIN_PROBS];
    let mut match_probs = [ProbEntry::new(); NUM_MATCH_PROBS];
    let mut lz_probs = [ProbEntry::new(); NUM_LZ_PROBS];
    let mut delta_probs = [ProbEntry::new(); NUM_DELTA_PROBS];
    let mut lz_rep_probs = [[ProbEntry::new(); NUM_LZ_REP_PROBS]; NUM_LZ_REP_DECISIONS];
    let mut delta_rep_probs = [[ProbEntry::new(); NUM_DELTA_REP_PROBS]; NUM_DELTA_REP_DECISIONS];

    let mut main_state = 0usize;
    let mut match_state = 0usize;
    let mut lz_state = 0usize;
    let mut delta_state = 0usize;
    let mut lz_rep_states = [0usize; NUM_LZ_REP_DECISIONS];
    let mut delta_rep_states = [0usize; NUM_DELTA_REP_DECISIONS];

    let mut lit_tree = Huffman::new(256, LITERAL_REBUILD);
    let mut lz_off_tree = Huffman::new(num_slots, LZ_OFFSET_REBUILD);
    let mut len_tree = Huffman::new(NUM_LENGTH_SYMS, LENGTH_REBUILD);
    let mut dlt_off_tree = Huffman::new(num_slots, DELTA_OFFSET_REBUILD);
    let mut dlt_pow_tree = Huffman::new(NUM_DELTA_POWER_SYMS, DELTA_POWER_REBUILD);

    let mut lz_offsets = [1u32, 2, 3, 4];
    let mut delta_pairs = [1u64, 2, 3, 4];

    let mut prev_item_type: u32 = 0;

    macro_rules! rbit {
        ($probs:expr, $state:expr, $n:expr) => {{
            let s = $state;
            $state = ($state << 1) & ($n - 1);
            let bit = rd.decode_bit(&mut $probs[s]);
            if bit == 1 {
                $state |= 1;
            }
            bit
        }};
    }

    let trace = std::env::var("LZMS_TRACE").is_ok();
    let mut item_count = 0usize;

    while out_pos < uncompressed_size {
        if rbit!(main_probs, main_state, NUM_MAIN_PROBS) == 0 {
            let sym = lit_tree.decode(&mut bits)?;
            if trace && item_count < 20 {
                eprintln!("item {item_count}: lit {sym:#04x} out_pos={out_pos}");
            }
            out[out_pos] = sym as u8;
            out_pos += 1;
            prev_item_type = 0;
            item_count += 1;
        } else if rbit!(match_probs, match_state, NUM_MATCH_PROBS) == 0 {
            let offset = if rbit!(lz_probs, lz_state, NUM_LZ_PROBS) == 0 {
                let slot = lz_off_tree.decode(&mut bits)?;
                let off = OFFSET_SLOT_BASE[slot] + bits.read(EXTRA_OFFSET_BITS[slot]);
                lz_offsets[3] = lz_offsets[2];
                lz_offsets[2] = lz_offsets[1];
                lz_offsets[1] = lz_offsets[0];
                off
            } else {
                let adj = (prev_item_type & 1) as usize;
                if rbit!(lz_rep_probs[0], lz_rep_states[0], NUM_LZ_REP_PROBS) == 0 {
                    let o = lz_offsets[0 + adj];
                    lz_offsets[0 + adj] = lz_offsets[0];
                    o
                } else if rbit!(lz_rep_probs[1], lz_rep_states[1], NUM_LZ_REP_PROBS) == 0 {
                    let o = lz_offsets[1 + adj];
                    lz_offsets[1 + adj] = lz_offsets[1];
                    lz_offsets[1] = lz_offsets[0];
                    o
                } else {
                    let o = lz_offsets[2 + adj];
                    lz_offsets[2 + adj] = lz_offsets[2];
                    lz_offsets[2] = lz_offsets[1];
                    lz_offsets[1] = lz_offsets[0];
                    o
                }
            };
            lz_offsets[0] = offset;
            let length_slot = len_tree.decode(&mut bits)?;
            let length =
                LENGTH_SLOT_BASE[length_slot] + bits.read(EXTRA_LENGTH_BITS[length_slot]) as u32;
            let off = offset as usize;
            if trace && (item_count < 20 || off > out_pos) {
                eprintln!(
                    "item {item_count}: LZ off={off} len={length} out_pos={out_pos} slot_base={}",
                    OFFSET_SLOT_BASE
                        .iter()
                        .position(|&x| x > offset)
                        .map(|p| OFFSET_SLOT_BASE[p - 1])
                        .unwrap_or(0)
                );
            }
            item_count += 1;
            if off == 0 || off > out_pos {
                if std::env::var("LZMS_TRACE").is_ok() {
                    eprintln!("LZ match fail: off={off} out_pos={out_pos} num_slots={num_slots}");
                }
                return Err(Error::Corrupt("LZ offset out of range"));
            }
            let length = length as usize;
            if out_pos + length > uncompressed_size {
                return Err(Error::Corrupt("LZ match overrun"));
            }
            for i in 0..length {
                out[out_pos + i] = out[out_pos - off + i];
            }
            out_pos += length;
            prev_item_type = 1;
        } else {
            let adj = (prev_item_type >> 1) as usize;
            let pair = if rbit!(delta_probs, delta_state, NUM_DELTA_PROBS) == 0 {
                let power = dlt_pow_tree.decode(&mut bits)? as u32;
                let slot = dlt_off_tree.decode(&mut bits)?;
                let raw = OFFSET_SLOT_BASE[slot] + bits.read(EXTRA_OFFSET_BITS[slot]);
                let p = ((power as u64) << 32) | raw as u64;
                delta_pairs[3] = delta_pairs[2];
                delta_pairs[2] = delta_pairs[1];
                delta_pairs[1] = delta_pairs[0];
                p
            } else {
                if rbit!(delta_rep_probs[0], delta_rep_states[0], NUM_DELTA_REP_PROBS) == 0 {
                    let p = delta_pairs[0 + adj];
                    delta_pairs[0 + adj] = delta_pairs[0];
                    p
                } else if rbit!(delta_rep_probs[1], delta_rep_states[1], NUM_DELTA_REP_PROBS) == 0 {
                    let p = delta_pairs[1 + adj];
                    delta_pairs[1 + adj] = delta_pairs[1];
                    delta_pairs[1] = delta_pairs[0];
                    p
                } else {
                    let p = delta_pairs[2 + adj];
                    delta_pairs[2 + adj] = delta_pairs[2];
                    delta_pairs[2] = delta_pairs[1];
                    delta_pairs[1] = delta_pairs[0];
                    p
                }
            };
            delta_pairs[0] = pair;

            let power = (pair >> 32) as u32;
            let raw_offset = pair as u32;
            let length_slot = len_tree.decode(&mut bits)?;
            let length = (LENGTH_SLOT_BASE[length_slot]
                + bits.read(EXTRA_LENGTH_BITS[length_slot]) as u32)
                as usize;

            let span = 1usize << power;
            let offset = match (raw_offset as usize).checked_shl(power) {
                Some(o) => o,
                None => return Err(Error::Corrupt("delta offset overflow")),
            };
            if offset.checked_add(span).is_none() {
                return Err(Error::Corrupt("delta offset+span overflow"));
            }
            if offset + span > out_pos {
                return Err(Error::Corrupt("delta offset out of range"));
            }
            if out_pos + length > uncompressed_size {
                return Err(Error::Corrupt("delta match overrun"));
            }

            let matchptr_base = out_pos - offset;
            for i in 0..length {
                let b = out[matchptr_base + i];
                let c = if matchptr_base + i >= span {
                    out[matchptr_base + i - span]
                } else {
                    0
                };
                let d = if out_pos + i >= span {
                    out[out_pos + i - span]
                } else {
                    0
                };
                out[out_pos + i] = b.wrapping_add(d).wrapping_sub(c);
            }
            out_pos += length;
            prev_item_type = 2;
        }
    }

    x86_filter_undo(&mut out);
    Ok(out)
}
