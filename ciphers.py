#!/usr/bin/env python

import re

# TODO: type-check retvals
# TODO: various test cases including pencil-and-paper key/digraphs
# TODO: raw_crypt vs formatted_crypt
# TODO: fivechunk -> also have linebreaks maybe every 10th fivechunk

# ================================================================
# UTILITY FUNCITONS

# ----------------------------------------------------------------
ALPHABET_WITHOUT_J = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'

# ----------------------------------------------------------------
def to_upper_alpha_clean(text: str):
    """
    TODO: comment semantics.
    TODO: comment use-cases (pt / kt).
    """
    if text == '':
        return text

    text = re.sub(r'[ \t\n,;:.\?!-]', '', text)

    text = text.replace('0', 'ZERO')
    text = text.replace('1', 'ONE')
    text = text.replace('2', 'TWO')
    text = text.replace('3', 'THREE')
    text = text.replace('4', 'FOUR')
    text = text.replace('5', 'FIVE')
    text = text.replace('6', 'SIX')
    text = text.replace('7', 'SEVEN')
    text = text.replace('8', 'EIGHT')
    text = text.replace('9', 'NINE')

    if not text.isalpha():
        raise Exception( f'Can only handle alphabetical+whitespace input: "{text}"')
    return text.upper()

# ----------------------------------------------------------------
def nsplit(text: str, n: int):
    return [text[i:i+n] for i in range(0, len(text), n)]

# ----------------------------------------------------------------
def fivechunk(text: str):
    return ' '.join(nsplit(text, 5))

# ----------------------------------------------------------------
def evenpad(text): # TODO: only for four-square; playfair needs repeated-character logic
    if len(text) % 2 == 0:
        return text
    else:
        return text + 'X'

# ----------------------------------------------------------------
def make_digraphs(text: str):
    return nsplit(evenpad(text), 2)

# ================================================================
class Vigenere:
    key: str
    def __init__(self, key):
        self.key = self.keyprep(key)

    def prep(self, text):
        return to_upper_alpha_clean(text)
    def keyprep(self, text):
        return self.prep(text)
    def ptprep(self, text):
        return self.prep(text)

    def encrypt(self, pt:str):
        return self.__crypt(pt, True)
    def decrypt(self, ct:str):
        return self.__crypt(ct, False)
    def __crypt(self, pt:str, forward: bool):
        pt = self.ptprep(pt)
        ptlen = len(pt)
        keylen = len(self.key)
        ctchars = ['*'] * ptlen
        ord_A = ord('A')
        for i in range(ptlen):
            ptchar = pt[i]
            keychar = self.key[i%keylen] # pad key repeatedly out to plaintext length
            # Treat A..Z as 0..25.
            # Cipherchar is (plainchar + keychar mod 26).
            # E.g. if plaintext is 'E' and key text is 'B' then ciphertext is 'F'.
            # An all-A's key results in ciphertext == plaintext.
            if forward:
                sum = ord(ptchar) + ord(keychar)
            else:
                sum = ord(ptchar) - ord(keychar)
            cipherchar = chr(ord_A + (sum % 26) )
            ctchars[i] = cipherchar
        return fivechunk("".join(ctchars))


# ================================================================
class Polybius:
    """
    Implements 5x5 Roman-alphabet Polybius square as used by the Playfair and Four-square ciphers.
    """
    square: list
    char_to_coords: dict
    def __init__(self, text):
        text = to_upper_alpha_clean(text)
        self.square = self.make_blank_square()
        seen = set()
        k = 0
        for char in text:
            if char not in seen:
                self.put_by_1d_index(k, char)
                k += 1
            seen.add(char)
        for char in ALPHABET_WITHOUT_J:
            if char not in seen:
                self.put_by_1d_index(k, char)
                k += 1
            seen.add(char)
        self.char_to_coords = {}
        for i in range(5):
            for j in range(5):
                self.char_to_coords[self.square[i][j]] = (i,j)
    def make_blank_square(self):
        return [ ['*' for j in range(5) ] for i in range(5) ]

    def __str__(self):
        return "\n".join([' '.join(row) for row in self.square])
    def __repr__(self):
        return self.__str__()

    def put_by_1d_index(self, index: int, char: str):
        # 0 1 2 3 4
        # 5 6 7 8 9
        # ..
        row_index = index // 5
        col_index = index % 5
        if row_index > 5:
            # Input wasn't squashed J -> I, or has punctuation unstripped, or somesuch.
            raise Exception('Polybius: unclean input')
        self.square[row_index][col_index] = char
    def get_coords(self, char: str):
        return self.char_to_coords[char]

# ----------------------------------------------------------------
class Playfair:
    """
    Playfair cipher with J mapped to I.
    See also: https://en.wikipedia.org/wiki/Playfair_cipher
    """
    square: Polybius
    def __init__(self, keytext):
        self.square = Polybius(self.keyprep(keytext))
    def __str__(self):
        return self.square.__str__()

    def prep(self, text):
        return to_upper_alpha_clean(text).replace('J', 'I')
    def keyprep(self, text):
        return self.prep(text)
    def ptprep(self, text):
        text = self.prep(text)
        if len(text) % 2 == 0:
            return text
        else:
            return text + 'X'

    def encrypt(self, pt:str):
        return self.__crypt(pt, True)
    def decrypt(self, pt:str):
        return self.__crypt(pt, False)
    def __crypt(self, pt:str, forward:bool):
        pt = self.ptprep(pt) # TODO: needs a playfairpad to 'X' between consecutives
        ctchars = []
        n = len(pt)
        shift = 1 if forward else -1
        for digraph in make_digraphs(pt):
            pt0 = digraph[0]
            pt1 = digraph[1]

            pt0i, pt0j = self.square.get_coords(pt0)
            pt1i, pt1j = self.square.get_coords(pt1)

            # G E M I N
            # A<B>C D F
            # H J K L O
            # P R S<T>U
            # V W X Y Z

            if pt0i == pt1i:
                if pt0j == pt1j: # same row, same col
                    # If we've already replace 'OO' with 'OXO' etc then what must be
                    # going on here is repeated X's in the plaintext, which, suffer.
                    # raise Exception(f'Playfair: input "{pt}" not X-deduped')
                    ct0i, ct0j = pt0i, pt0j
                    ct1i, ct1j = pt1i, pt1j
                else: # same row
                    ct0i, ct0j = (pt0i, (pt0j+shift)%5)
                    ct1i, ct1j = (pt1i, (pt1j+shift)%5)
            else:
                if pt0j == pt1j: # same col
                    ct0i, ct0j = ((pt0i+shift)%5, pt0j)
                    ct1i, ct1j = ((pt1i+shift)%5, pt1j)
                else: # rectangle
                    ct0i, ct0j = (pt0i, pt1j)
                    ct1i, ct1j = (pt1i, pt0j)

            ct0 = self.square.square[ct0i][ct0j]
            ct1 = self.square.square[ct1i][ct1j]

            ctchars.append(ct0)
            ctchars.append(ct1)

        return fivechunk("".join(ctchars))

# ----------------------------------------------------------------
class Foursquare:
    """
    Four-square cipher with J mapped to I.
    See also: https://en.wikipedia.org/wiki/Four-square_cipher
    """
    ul: Polybius
    ur: Polybius
    ll: Polybius
    lr: Polybius
    def __init__(self, urkeytext, llkeytext):
        self.ul = Polybius(ALPHABET_WITHOUT_J)
        self.ur = Polybius(urkeytext)
        self.ll = Polybius(llkeytext)
        self.lr = Polybius(ALPHABET_WITHOUT_J)
    def __str__(self):
        lines = []
        for i in range(5):
            left  = ' '.join(self.ul.square[i]).lower()
            right = ' '.join(self.ur.square[i])
            lines.append(left + '   ' + right)
        lines.append("")
        for i in range(5):
            left  = ' '.join(self.ll.square[i])
            right = ' '.join(self.lr.square[i]).lower()
            lines.append(left + '   ' + right)
        return "\n".join(lines)

    def prep(self, text):
        return to_upper_alpha_clean(text).replace('J', 'I')
    def keyprep(self, text):
        return self.prep(text)
    def ptprep(self, text):
        text = self.prep(text)
        if len(text) % 2 == 0:
            return text
        else:
            return text + 'X'

    def encrypt(self, pt):
        return self.__crypt(pt, self.ul, self.ur, self.ll, self.lr)
    def decrypt(self, pt):
        return self.__crypt(pt, self.ur, self.ul, self.lr, self.ll)
    def __crypt(self, pt, ul, ur, ll, lr):
        # plaintext 'HE' goes to ciphertext 'FY'
        #
        # a b c d e   E X A M P
        # f g<h>i j   L B C D<F>
        # k l m n o   G H I J K
        # p r s t u   N O R S T
        # v w x y z   U V W Y Z
        #
        # K E<Y>W O   a b c d<e>
        # R D A B C   f g h i j
        # F G H I J   k l m n o
        # L M N P S   p r s t u
        # T U V X Z   v w x y z
        pt = self.ptprep(pt)
        ctchars = []
        n = len(pt)
        for digraph in make_digraphs(pt):
            pt0 = digraph[0]
            pt1 = digraph[1]

            pt0i, pt0j = ul.get_coords(pt0)
            pt1i, pt1j = lr.get_coords(pt1)

            ct0i , ct0j = (pt0i, pt1j)
            ct1i , ct1j = (pt1i, pt0j)

            ct0 = ur.square[ct0i][ct0j]
            ct1 = ll.square[ct1i][ct1j]

            ctchars.append(ct0)
            ctchars.append(ct1)

        return fivechunk("".join(ctchars))


# ================================================================
def vigtest():
    vig = Vigenere('the quick brown fox jumped over the lazy dogs')
    pt  = 'the rain in spain falls mainly on the plain'
    ct  = vig.encrypt(pt)
    pt2 = vig.decrypt(ct)

    assert(ct  == 'MOIHU QPSOJ DWVST XUFEB ELBGC FGALP PKYLB')
    assert(pt2 == 'THERA ININS PAINF ALLSM AINLY ONTHE PLAIN')
    print('OK test vigenere')

def pstest():
    s = Polybius('GEMINI')
    assert(s.__repr__() == 'G E M I N\nA B C D F\nH K L O P\nQ R S T U\nV W X Y Z')
    print('OK test polybius')

def pftest():
    pf = Playfair('the quick brown fox jumped over the lazy dogs')
    # pt = 'Hello, world!'
    pt = 'Helxlo, world!'
    ct = pf.encrypt(pt)
    assert(ct == 'EQSLM XNWXS LN')
    pt2 = pf.decrypt(ct)
    assert(pt2 == 'HELXL OWORL DX')
    print('OK test playfair')

def fstest():
    fs = Foursquare('GEMINI', 'AQUILA')
    pt = 'Hello, world!'
    ct = fs.encrypt(pt)
    assert(ct == 'FUHGK YKSOA')
    pt2 = fs.decrypt(ct)
    assert(pt2 == 'HELLO WORLD')
    print('OK test foursquare')

def testall():
    vigtest()
    pstest()
    pftest()
    fstest()
    print('OK test all')

# ================================================================
# use python -i
