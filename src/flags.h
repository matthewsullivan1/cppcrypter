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
    FLAG_COUNT
};

extern bool flags[FLAG_COUNT];

#endif // FLAGS_H
