#pragma once
#include <stdio.h>

#define LOG_ERROR(fmt, ...) fprintf(stderr, fmt "\r\n", __VA_ARGS__)
