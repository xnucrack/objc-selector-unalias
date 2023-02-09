document = Document.getCurrentDocument()


OPCODE_SIGNATURE_AARCH64 = [
    'adrp',
    'ldr',
    'adrp',
    'ldr',
    'br'
]

OPCODE_SIGNATURE_AARCH64E = [
    'adrp',
    'ldr',
    'adrp',
    'add',
    'ldr'
]


class NoSelectorError(Exception):
    pass


class AliasCriteriaError(Exception):
    pass


class NoMethodNameError(Exception):
    pass


def read_string(address: int)->str:

    result = bytearray()
    start = address

    while (x := document.readByte(start)) != 0x00:
        result += chr(x).encode()
        start += 1

    return result.decode()


def getselector_aarch64(procedure: Procedure):

    text_segment = document.getSegmentByName("__TEXT")

    bb = procedure.getBasicBlock(0)
    base = bb.getStartingAddress()

    # Check if the instructions satisfy the opcode signature...
    bb_opcodes = [text_segment.getInstructionAtAddress(base + i * 4).getInstructionString() for i in range(5)]

    if bb_opcodes not in [OPCODE_SIGNATURE_AARCH64, OPCODE_SIGNATURE_AARCH64E]:
        raise AliasCriteriaError

    # Get the Objective-C selector being aliased.
    i_1 = text_segment.getInstructionAtAddress(base)
    i_2 = text_segment.getInstructionAtAddress(base + 4)

    if ', ' in i_2.getRawArgument(1):
        offset = int(i_2.getRawArgument(1).split(', ')[1][1:-1], 16)
    else:
        offset = 0

    selector_address = int(i_1.getRawArgument(1)[1:], 16) + offset

    # check to make sure the address is an Objective-c selector
    if document.getSectionAtAddress(selector_address).getName() != "__objc_selrefs":
        raise NoSelectorError

    selector_seg = document.getSegmentAtAddress(selector_address)
    refs_from = selector_seg.getReferencesFromAddress(selector_address)

    if len(refs_from) == 0:
        raise NoMethodNameError

    # Ensure the cross-reference is in the appropriate section for Objective-C method names.
    i = 0
    while document.getSectionAtAddress(refs_from[i]).getName() != "__objc_methname" and i < len(refs_from):
        i += 1

    if i == len(refs_from):
        raise NoMethodNameError

    selector_name = read_string(refs_from[i])
    return selector_name


def analyze_procedures():

    text_segment = document.getSegmentByName('__TEXT')

    renamed_count = 0

    for p in range(text_segment.getProcedureCount()):
        procedure = text_segment.getProcedureAtIndex(p)

        if procedure.getBasicBlockCount() > 1:
            continue

        procedure_bb = procedure.getBasicBlock(0)

        architecture = text_segment \
            .getInstructionAtAddress(procedure_bb.getStartingAddress()) \
            .getArchitecture()

        if architecture == 5:

            # Verify that the basic block is the appropriate length for an alias function.
            if procedure_bb.getEndingAddress() - procedure_bb.getStartingAddress() not in [16, 20]:
                continue

            try:
                selector = getselector_aarch64(procedure)
                print(f"[INFO] Found alias procedure at {hex(procedure.getEntryPoint())} ({selector}).")
                document.setNameAtAddress(procedure.getEntryPoint(), f"ALIAS__{selector}")
                renamed_count += 1
            except Exception as e:
                print(f"[ERROR] Address: {hex(procedure.getEntryPoint())}, Type: {type(e).__name__}")

    print(f"[INFO] Renamed {renamed_count} Objective-C selector aliases.")


analyze_procedures()
