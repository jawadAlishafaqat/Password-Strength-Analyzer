# Password Strength Analyzer Configuration

MIN_LENGTH = 8
RECOMMENDED_LENGTH = 15

SCORE = {

    "LENGTH_15":30,
    "LENGTH_12":20,
    "LENGTH_8":10,

    "UPPERCASE":10,
    "LOWERCASE":10,
    "DIGIT":10,
    "SYMBOL":10,

    "DICTIONARY":-20,
    "KEYBOARD":-15,
    "SEQUENTIAL":-15,
    "REPEATED":-10,
    "PATTERN":-10

}

STRENGTH = {

    "VERY_WEAK":20,
    "WEAK":40,
    "MODERATE":60,
    "STRONG":80,
    "EXCELLENT":100

}
