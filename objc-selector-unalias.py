document = Document.getCurrentDocument()


OPCODE_SIGNATURE_AARCH64 = [
    'adrp',
    'ldr',
    'adrp',
    'ldr',
    'br'
]


def read_string(address: int)->str:

    result = bytearray()
    start = address

    while (x := document.readByte(start)) != 0x00:
        result += chr(x).encode()
        start += 1

    return result.decode()


def getselector_aarch64(procedure: Procedure):

    text_segment = document.getSegmentByName("__TEXT")

    # Verify that the basic block is the appropriate length for an alias function.
    bb = procedure.getBasicBlock(0)
    if bb.getEndingAddress() - bb.getStartingAddress() != 16:
        return None

    base = bb.getStartingAddress()

    # Check if the instructions satisfy the opcode signature...
    bb_opcodes = [text_segment.getInstructionAtAddress(base + i * 4).getInstructionString() for i in range(5)]

    if bb_opcodes != OPCODE_SIGNATURE_AARCH64:
        return None

    # Get the Objective-C selector being aliased.

    i_1 = text_segment.getInstructionAtAddress(base)
    i_2 = text_segment.getInstructionAtAddress(base + 4)

    selector_address = int(i_1.getRawArgument(1)[1:], 16) + int(i_2.getRawArgument(1).split(', ')[1][1:-1], 16)

    selector_seg = document.getSegmentAtAddress(selector_address)
    ref_from = selector_seg.getReferencesFromAddress(selector_address)[0]

    selector_name = read_string(ref_from)
    return selector_name


def analyze_procedures():

    text_segment = document.getSegmentByName('__TEXT')

    for p in range(text_segment.getProcedureCount()):
        # print("this executed 1")
        procedure = text_segment.getProcedureAtIndex(p)

        if procedure.getBasicBlockCount() > 1:
            continue
        # print("this executed 2")

        procedure_bb = procedure.getBasicBlock(0)

        architecture = text_segment\
            .getInstructionAtAddress(procedure_bb.getStartingAddress())\
            .getArchitecture()
        print(f"arch: {architecture}")

        if architecture == 5:
            try:
                selector = getselector_aarch64(procedure)
                print(f"Found alias procedure at {hex(procedure.getEntryPoint())} ({selector}).")
                document.setNameAtAddress(procedure.getEntryPoint(), f"ALIAS__{selector}")
            except Exception as e:
                print(f"Error occurred. Address: {hex(procedure.getEntryPoint())}, Type: {type(e)}")


analyze_procedures()
