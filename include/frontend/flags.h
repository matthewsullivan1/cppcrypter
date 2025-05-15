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
    NAME,
    FLAG_COUNT
};




// flags[] is for checking whether or not the flag was used, insertions[] is updated by flags[],
// since there are multipe segments that need to be inserted per single flag being set, rather than
// checking at every single line, if the flag is true, and the line matches the placeholder for the 
// insertion, individual flags can be used to mark that the segment has already been inserted, and 
// the loop can continue without checking the line for that insertion  
extern bool flags[FLAG_COUNT];

#endif // FLAGS_H
