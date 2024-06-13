#ifndef PLACEHOLDERS_H
#define PLACEHOLDERS_H


enum PlaceHolders {
    RAND_DEF_POS,
    RAND_CALL_POS,
    VM_DEF_POS,
    VM_CALL_POS,
    DB_DEF_POS,
    DB_CALL_POS,
    DYN_GLOBALS_POS,
    DYN_CALL_POS,
    API_CALLS_POS,
    DWORD_ARRAY_POS,
    PLACEHOLDER_COUNT
};

// flags[] is for checking whether or not the flag was us placeholders[] is updated by flags[],
// since there are multipe segments that need to be inserted per single flag being set, rather than
// checking at every single line, if the flag is true, and the line matches the placeholder for the 
// insertion, individual flags can be used to mark that the segment has already been inserted, and 
// the loop can continue without checking the line for that insertion  
extern bool placeholders[PLACEHOLDER_COUNT];

#endif // PLACEHOLDERS_H
