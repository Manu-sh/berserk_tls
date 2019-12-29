#pragma once

#include <stdio.h>
#define LOG(_STREAM_, _STRERROR_) (fprintf((_STREAM_), "%s\n", (_STRERROR_)))