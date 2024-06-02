#ifndef FLAGS_H
#define FLAGS_H

enum Flag {
    RAND,
    VM,
    DB,
    DYN,
    COMPILE,
    PAYLOAD,
    STUB,
    HELP,
    PATH,
    PDB,
    FLAG_COUNT
};

enum PlaceHolders {
    RAND_DEF_POS,
    RAND_CALL_POS,
    VM_DEF_POS,
    VM_CALL_POS,
    DB_DEF_POS,
    DB_CALL_POS,
    DYN_GLOBALS_POS,
    DYN_RESOLUTION_POS,
    INSERTION_COUNT
};


extern bool flags[FLAG_COUNT];
extern bool insertions[INSERTION_COUNT];

#endif // FLAGS_H
