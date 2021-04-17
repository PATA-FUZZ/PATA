# PATA

PATA is a novel fuzzer that expands coverage with path-aware taint inference. It first identifies variables used by constraints and collects paths by recording values of each occurrence of them. Then it infers critical bytes for each constraint variable occurrence in the path by analyzing runtime values.  Finally, it employs a path-oriented mutation. Combining with variable features and occurrence values, PATA precisely mutates critical bytes of constraint variables to explore the uncovered states along the path of the input.

In the evaluation of  Google fuzzer-test-suite, PATA is compared with AFL, MOPT, TortoiseFuzz, VUzzer, Angora, Redqueen, and GREYONE. The initial seeds for each project could be found in the "seeds" directory. The 24-hour experiment is conducted 5 times and PATA finds more paths, basic blocks, and bugs than others. Below are bugs find by PATA and corresponding calling stack or analysis.

## Bugs found by PATA in FTS and corresponding calling stack or analysis 

### cares

```c
int ares_create_query(const char *name, int dnsclass, int type,
                      unsigned short id, int rd, unsigned char **buf,
                      int *buflen, int max_udp_size)
{
  int len;
  unsigned char *q;
  const char *p;

  *buflen = 0;
  *buf = NULL;

  len = 1;
  for (p = name; *p; p++)
    {
      if (*p == '\\' && *(p + 1) != 0)
        p++; // Encountered the character, but not calculated into len    
      len++;
    }
    
  if (*name && *(p - 1) != '.')
    len++; // When ending with '.', it doesn't count into len, resulting in one less len
  
  ...
```

### guetzli

#### Bug 1

```c++
// output_image.c, line 395

for (int k = 0; k < kDCTBlockSize; ++k) {
    const int quant = q[c][k];
    int coeff = src_coeffs[k];
    assert(coeff % quant == 0);  // Triggers the assert
    dest_coeffs[k] = coeff / quant;
}
```

### json

#### Bug 1

The crash is related to the precision of execution, and the statement of crash appears in fuzzy parse_ json.cpp.

```cpp
// fuzzer-parse_json.cpp, line 34

json j1 = json::parse(data, data + size); // data = "10000000000000001200012001000010001001000120000100"

// first serialization
std::string s1 = j1.dump(); // s1 = "1e+49"

// parse serialization
json j2 = json::parse(s1);

// second serialization
std::string s2 = j2.dump(); // s2 = "9.999999999999999e+48", The precision of different library functions is slightly different。

// serializations must match
assert(s1 == s2); // So it triggered a crash here
```

#### Bug 2

If the input data is too large, the stack will burst in the process of JSON parse recursion.

### lcms

```cpp
// cmsintrp.c, line 590
#define DENS(i,j,k) (LutTable[(i)+(j)+(k)+OutChan]) // Macro definition. Outchan equals 0 at crash


// cmsintrp.c, line 647
if (rz >= rx && rx >= ry) {

    c1 = DENS(X1, Y0, Z1) - DENS(X0, Y0, Z1);
    c2 = DENS(X1, Y1, Z1) - DENS(X1, Y0, Z1); // When crash file is run as input, the corresponding allocated heap space size of luttable is 96 bytes. When accessing here, X1 + Y1 + Z1 = 27, offset is 27 * 4 = 108 bytes, which is out of bounds.
    c3 = DENS(X0, Y0, Z1) - c0;

}
```

### libxml2

#### bug 1

```cpp
// dict.c, line 477
static unsigned long
xmlDictComputeFastQKey(const xmlChar *prefix, int plen,
                       const xmlChar *name, int len, int seed)
{
    unsigned long value = (unsigned long) seed;

    if (plen == 0)
   value += 30 * (unsigned long) ':';
    else
   value += 30 * (*prefix);

    if (len > 10) {
        value += name[len - (plen + 1 + 1)];  // The input that causes a crash, where plen = 1013, len = 35, is accessed in negative coordinates.
        /* 
        
        int offset = len - (plen + 1 + 1);
		if (offset < 0)
	    	offset = len - (10 + 1);
		value += name[offset];
        */
        len = 10;
   if (plen > 10)
       plen = 10;
    }
```

#### bug 2

```c
void xmlParseContent(xmlParserCtxtPtr ctxt) {
  while ((RAW != 0) && ((RAW != '<') || /*...*/)) {
    //...
    if ((*cur == '<') && (cur[1] == '?')) {
      //...
    }
    else if (*cur == '<') {
      if (/*...*/) {return;}
      xmlParseContent(ctxt);
      if (ctxt->sax2) {
        if ((tlen >0) &&
           (xmlStrncmp(ctxt->input, ctxt->name, tlen) == 0)) {
           if (ctxt->input[len] == '>') // <= OVERFLOW
           //...
        }
      }
    }
    // ...
  }
}
```

Listing above shows one bug of *libxml2* which is only found by PATA.
The bug will be triggered when *tlen* exceeds the length of *ctxt->input*. The bug is very difficult to find because it has lots of preconditions. For instance, the condition in line 2 (logical operation), line 7 (byte comparison), line 10 (logical operation), line 11 (integer comparison), and line 12 (byte-array comparison) should all be satisfied. In particular, the constraint variables related to these conditions all occur multiple times because of the loop and the recursive call. It is difficult for other fuzzers to detect bugs in such deep paths without the path-aware taint analysis of PATA.

#### bug 3

```cpp
// parser.c line 10652

GROW;

SKIP_BLANKS;
ctxt->input->standalone = xmlParseSDDecl(ctxt);

SKIP_BLANKS;
if ((RAW == '?') && (NXT(1) == '>')) {
    SKIP(2);
} else if (RAW == '>') {
    /* Deprecated old WD ... */
	xmlFatalErr(ctxt, XML_ERR_XMLDECL_NOT_FINISHED, NULL);
	NEXT;
} else {
	xmlFatalErr(ctxt, XML_ERR_XMLDECL_NOT_FINISHED, NULL);
	MOVETO_ENDTAG(CUR_PTR); // CUR_PTR is an invalid pointer after a series of operations. CUR_ PTR = ctxt->cur
	NEXT;
}
```

### libcxxabi

#### bug 1
```sh
parse_builtin_type<__cxxabiv1::(anonymous namespace)::Db> @ 0x000000000053ef94
Stack Head (1000 entries):
   parse_builtin_type<__cxxa @ 0x000000000053ef94
   parse_type<__cxxabiv1::(a @ 0x00000000004d0672
   parse_function_type<__cxx @ 0x00000000004d4c6b
   parse_type<__cxxabiv1::(a @ 0x00000000004d4c6b
   parse_function_type<__cxx @ 0x00000000004d4f24
   parse_type<__cxxabiv1::(a @ 0x00000000004d4f24
   parse_encoding<__cxxabiv1 @ 0x00000000004cb907
   parse_local_name<__cxxabi @ 0x00000000004e8347
   parse_name<__cxxabiv1::(a @ 0x00000000004e8347
   parse_type<__cxxabiv1::(a @ 0x00000000004dfed9
   parse_function_type<__cxx @ 0x00000000004d4f24
   parse_type<__cxxabiv1::(a @ 0x00000000004d4f24
   parse_function_type<__cxx @ 0x00000000004d4f24
   parse_type<__cxxabiv1::(a @ 0x00000000004d4f24
   parse_function_type<__cxx @ 0x00000000004d4f24
   parse_type<__cxxabiv1::(a @ 0x00000000004d4f24
```

#### bug 2
```sh
parse_expression<__cxxabiv1::(anonymous namespace)::Db> @ 0x00000000004fe923
Stack Head (751 entries):
   parse_expression<__cxxabi @ 0x00000000004fe923
   parse_expression<__cxxabi @ 0x0000000000504254
   parse_expression<__cxxabi @ 0x0000000000504254
   parse_expression<__cxxabi @ 0x0000000000504254
   parse_expression<__cxxabi @ 0x0000000000504254
   parse_expression<__cxxabi @ 0x0000000000504254
   parse_expression<__cxxabi @ 0x0000000000504254
   parse_expression<__cxxabi @ 0x0000000000504254
   parse_expression<__cxxabi @ 0x0000000000504254
   parse_expression<__cxxabi @ 0x0000000000504254
   parse_expression<__cxxabi @ 0x0000000000504254
   parse_expression<__cxxabi @ 0x0000000000504254
   parse_expression<__cxxabi @ 0x0000000000504254
   parse_expression<__cxxabi @ 0x0000000000504254
   parse_expression<__cxxabi @ 0x0000000000504254
   parse_expression<__cxxabi @ 0x0000000000504254
```

#### bug 3
```sh
parse_binary_expression<__cxxabiv1::(anonymous namespace)::Db> @ 0x000000000052c09c
Stack Head (1000 entries):
   parse_binary_expression<_ @ 0x000000000052c09c
   parse_expression<__cxxabi @ 0x0000000000502c2a
   parse_binary_expression<_ @ 0x000000000052c133
   parse_expression<__cxxabi @ 0x0000000000502c2a
   parse_binary_expression<_ @ 0x000000000052c133
   parse_expression<__cxxabi @ 0x0000000000502c2a
   parse_binary_expression<_ @ 0x000000000052c133
   parse_expression<__cxxabi @ 0x0000000000502c2a
   parse_binary_expression<_ @ 0x000000000052c133
   parse_expression<__cxxabi @ 0x0000000000502c2a
   parse_binary_expression<_ @ 0x000000000052c133
   parse_expression<__cxxabi @ 0x0000000000502c2a
   parse_binary_expression<_ @ 0x000000000052c133
   parse_expression<__cxxabi @ 0x0000000000502c2a
   parse_binary_expression<_ @ 0x000000000052c133
   parse_expression<__cxxabi @ 0x0000000000502c2a
```

#### bug 4
```sh
parse_encoding<__cxxabiv1::(anonymous namespace)::Db> @ 0x00000000004ca7bb
Stack Head (1000 entries):
   parse_encoding<__cxxabiv1 @ 0x00000000004ca7bb
   parse_local_name<__cxxabi @ 0x00000000004e8347
   parse_name<__cxxabiv1::(a @ 0x00000000004e8347
   parse_encoding<__cxxabiv1 @ 0x00000000004cac5b
   parse_local_name<__cxxabi @ 0x00000000004e8347
   parse_name<__cxxabiv1::(a @ 0x00000000004e8347
   parse_encoding<__cxxabiv1 @ 0x00000000004cac5b
   parse_local_name<__cxxabi @ 0x00000000004e8347
   parse_name<__cxxabiv1::(a @ 0x00000000004e8347
   parse_encoding<__cxxabiv1 @ 0x00000000004cac5b
   parse_local_name<__cxxabi @ 0x00000000004e8347
   parse_name<__cxxabiv1::(a @ 0x00000000004e8347
   parse_encoding<__cxxabiv1 @ 0x00000000004cac5b
   parse_local_name<__cxxabi @ 0x00000000004e8347
   parse_name<__cxxabiv1::(a @ 0x00000000004e8347
   parse_encoding<__cxxabiv1 @ 0x00000000004cac5b
```

#### bug 5
```sh
parse_name<__cxxabiv1::(anonymous namespace)::Db> @ 0x00000000004e80bb
Stack Head (1000 entries):
   parse_name<__cxxabiv1::(a @ 0x00000000004e80bb
   parse_encoding<__cxxabiv1 @ 0x00000000004cac5b
   parse_local_name<__cxxabi @ 0x00000000004e8347
   parse_name<__cxxabiv1::(a @ 0x00000000004e8347
   parse_encoding<__cxxabiv1 @ 0x00000000004cac5b
   parse_local_name<__cxxabi @ 0x00000000004e8347
   parse_name<__cxxabiv1::(a @ 0x00000000004e8347
   parse_type<__cxxabiv1::(a @ 0x00000000004dfed9
   parse_encoding<__cxxabiv1 @ 0x00000000004cb907
   parse_local_name<__cxxabi @ 0x00000000004e8347
   parse_name<__cxxabiv1::(a @ 0x00000000004e8347
   parse_type<__cxxabiv1::(a @ 0x00000000004dfed9
   parse_encoding<__cxxabiv1 @ 0x00000000004cb907
   parse_local_name<__cxxabi @ 0x00000000004e8347
   parse_name<__cxxabiv1::(a @ 0x00000000004e8347
   parse_encoding<__cxxabiv1 @ 0x00000000004cac5b
```
#### bug 6
```sh
parse_operator_name<__cxxabiv1::(anonymous namespace)::Db> @ 0x0000000000536040
Stack Head (1000 entries):
   parse_operator_name<__cxx @ 0x0000000000536040
   parse_unqualified_name<__ @ 0x00000000004f96da
   parse_unscoped_name<__cxx @ 0x00000000004e86cc
   parse_name<__cxxabiv1::(a @ 0x00000000004e86cc
   parse_type<__cxxabiv1::(a @ 0x00000000004dfed9
   parse_encoding<__cxxabiv1 @ 0x00000000004cb907
   parse_local_name<__cxxabi @ 0x00000000004e8347
   parse_name<__cxxabiv1::(a @ 0x00000000004e8347
   parse_encoding<__cxxabiv1 @ 0x00000000004cac5b
   parse_local_name<__cxxabi @ 0x00000000004e8347
   parse_name<__cxxabiv1::(a @ 0x00000000004e8347
   parse_type<__cxxabiv1::(a @ 0x00000000004dfed9
   parse_encoding<__cxxabiv1 @ 0x00000000004cb907
   parse_local_name<__cxxabi @ 0x00000000004e8347
   parse_name<__cxxabiv1::(a @ 0x00000000004e8347
   parse_type<__cxxabiv1::(a @ 0x00000000004dfed9
```

#### bug 7
```sh
parse_prefix_expression<__cxxabiv1::(anonymous namespace)::Db> @ 0x000000000052e665
Stack Head (1000 entries):
   parse_prefix_expression<_ @ 0x000000000052e665
   parse_expression<__cxxabi @ 0x00000000005026b9
   parse_prefix_expression<_ @ 0x000000000052e6e0
   parse_expression<__cxxabi @ 0x00000000005026b9
   parse_prefix_expression<_ @ 0x000000000052e6e0
   parse_expression<__cxxabi @ 0x00000000005026b9
   parse_prefix_expression<_ @ 0x000000000052e6e0
   parse_expression<__cxxabi @ 0x00000000005026b9
   parse_binary_expression<_ @ 0x000000000052c133
   parse_expression<__cxxabi @ 0x00000000005000ee
   parse_prefix_expression<_ @ 0x000000000052e6e0
   parse_expression<__cxxabi @ 0x00000000005026b9
   parse_prefix_expression<_ @ 0x000000000052e6e0
   parse_expression<__cxxabi @ 0x00000000005026b9
   parse_binary_expression<_ @ 0x000000000052c133
   parse_expression<__cxxabi @ 0x00000000005000ee
```



## openssl-1.0.1f

```cpp
// t1_lib.c, line 2553
int
tls1_process_heartbeat(SSL *s)
   {
   unsigned char *p = &s->s3->rrec.data[0], *pl;
   unsigned short hbtype;
   unsigned int payload;
   unsigned int padding = 16;


   hbtype = *p++;
   n2s(p, payload); // N2S converts the two byte data of address `p` into a 16 bit positive number and stores it in the payload. By constructing data, we can make the value of payload very large.
   pl = p;
    
    ...;
   
   *bp++ = TLS1_HB_RESPONSE;
   s2n(payload, bp);
   memcpy(bp, pl, payload); // Because the payload is too large, the memcpy here causes cross-border access. Trigger the heap buffer overflow of Asan.
   bp += payload;

   RAND_pseudo_bytes(bp, padding);
```

## openssl-1.0.2d

```asm
# crypto/bn/asm/x86_64-mont.pl, line 1490
.align	32
.L8x_tail_done:
	add	(%rdx),%r8		# can this overflow?
	xor	%rax,%rax
	# In later bug fixes, the XOR statement above was changed to the following statement:
  # adc	\$0,%r9
	# xor	%rax,%rax
	# adc	\$0,%r10
	# adc	\$0,%r11 
	# adc	\$0,%r12
	# adc	\$0,%r13
	# adc	\$0,%r14
	# adc	\$0,%r15
	# sbb	%rax,%rax
```

### pcre2
#### bug 1
```sh
__sanitizer::Abort() @ 0x00000000004b1937
Stack Head (14 entries):
   raise                     @ 0x00007ffff7ab9ef5: in (BL)
   abort                     @ 0x00007ffff7aa3862: in (BL)
   __sanitizer::Abort()      @ 0x00000000004b1937
   __sanitizer::Die()        @ 0x00000000004b0341
   ~ScopedInErrorReport      @ 0x0000000000499d69
   ReportGenericError        @ 0x000000000049926b
   __asan_report_load1       @ 0x0000000000499ee8
   match                     @ 0x00000000005587fa
   match                     @ 0x0000000000542239
   match                     @ 0x000000000054277d
   pcre2_match_8             @ 0x0000000000516392
   regexec                   @ 0x000000000056de11
   LLVMFuzzerTestOneInput    @ 0x00000000004c659d
   main                      @ 0x000000000056eea7
```
By constructing special data, the character pointer can be decremented until the effective heap space is exceeded.

```c
// pcre_match.c, line 5968

for(;;)
  {
  if (eptr == pp) goto TAIL_RECURSE;
  RMATCH(eptr, ecode, offset_top, mb, eptrb, RM46);
  if (rrc != MATCH_NOMATCH) RRETURN(rrc);
  eptr--; // By constructing data, decrement leads to invalid pointer and access to invalid memory
  BACKCHAR(eptr); // The macro here accesses the address pointed by the pointer, triggering the heap buffer overflow of Asan
  if (ctype == OP_ANYNL && eptr > pp  && UCHAR21(eptr) == CHAR_NL &&
      UCHAR21(eptr - 1) == CHAR_CR) eptr--;
  }
```



#### bug 2

```sh
__sanitizer::Abort() @ 0x00000000004b1937
Stack Head (14 entries):
   raise                     @ 0x00007ffff7ab9ef5: in (BL)
   abort                     @ 0x00007ffff7aa3862: in (BL)
   __sanitizer::Abort()      @ 0x00000000004b1937
   __sanitizer::Die()        @ 0x00000000004b0341
   ~ScopedInErrorReport      @ 0x0000000000499d69
   ReportGenericError        @ 0x000000000049926b
   __asan_report_load1       @ 0x0000000000499ee8
   find_minlength            @ 0x0000000000565cc8
   find_minlength            @ 0x00000000005650af
   _pcre2_study_8            @ 0x000000000055f1f2
   pcre2_compile_8           @ 0x00000000004d0f12
   regcomp                   @ 0x000000000056d8d6
   LLVMFuzzerTestOneInput    @ 0x00000000004c6541
   main                      @ 0x000000000056eea7
```



Recursion caused by special data. The function find_minlength() will be recursively called: find_ minlength() (pcre2_ study.c, line 433), find_ minlength() (pcre2_ study.c, line 433), find_ minlength() (pcre_ study.c, line 135), find_ minlength() (pcre_ study. c, line 135) until the stack bursts.

This function takes a parameter recurse_ depth to represent the depth of the current regular expression . But in addition to RECURSE, backreference also causes recursion, which is not considered by the program. In the later bug fix, the code also takes backreference into account, and the recursion in this case will increase automatically_ depth to avoid infinite recursion.

The bug is fixed in the commit https://vcs.pcre.org/pcre2/code/trunk/src/pcre2_study.c?r1=188&r2=189.

```c
// pcre_study.c, line 85

static int
find_minlength(const pcre2_real_code *re, PCRE2_SPTR code,
  PCRE2_SPTR startcode, int recurse_depth, BOOL utf)
{
    ...
    switch (*cc) 
    {
    ...
    case OP_DNREFI:
    ...
		// line 409
		int dd = find_minlength(re, cs, startcode, recurse_depth, utf);
    ...
	case OP_REFI:
        // line 433
		d = find_minlength(re, cs, startcode, recurse_depth, utf); // These two places are recursion caused by backreference, which may lead to infinite recursion when the depth restriction is not used.
    ...
    }
    
    ...
```



#### bug 3

```sh
__sanitizer::Abort() @ 0x00000000004b1937
Stack Head (15 entries):
   raise                     @ 0x00007ffff7ab9ef5: in (BL)
   abort                     @ 0x00007ffff7aa3862: in (BL)
   __sanitizer::Abort()      @ 0x00000000004b1937
   __sanitizer::Die()        @ 0x00000000004b0341
   ~ScopedInErrorReport      @ 0x0000000000499d69
   ReportGenericError        @ 0x000000000049926b
   __asan_report_load1       @ 0x0000000000499ee8
   find_fixedlength          @ 0x00000000004d5029
   find_fixedlength          @ 0x00000000004d4766
   find_fixedlength          @ 0x00000000004d4766
   find_fixedlength          @ 0x00000000004d4766
   pcre2_compile_8           @ 0x00000000004d0485
   regcomp                   @ 0x000000000056d8d6
   LLVMFuzzerTestOneInput    @ 0x00000000004c6541
   main                      @ 0x000000000056eea7
```

Fuzz calls the interface for compiling regular expressions. The function find is made by specially constructed find_ fixedlength (pcre2_ compile. c) is called recursively to cause stack explosion.

The principle is in the case of pcre2_ NO_ UTF_ CHECK, the program loops continuously by injecting invalid UTF string.

The bug was fixed in version 192 by checking the validity of UTF strings. See also https://vcs.pcre.org/pcre2/code/trunk/src/pcre2_compile.c?r1=190&r2=192。

The official description of the bug is as follows:：

> If a bad UTF string is compiled with NO_UTF_CHECK, it may succeed, but scanning the compiled pattern in subsequent auto-possessification can get out of step and lead to an unknown opcode. Previously this could have caused an infinite loop. Now it generates an "internal error" error. This is a tidyup, not a bug fix; passing bad UTF with NO_UTF_CHECK is documented as having an undefined outcome.



#### bug 4

```sh
__sanitizer::Abort() @ 0x00000000004b1937
Stack Head (17 entries):
   raise                     @ 0x00007ffff7ab9ef5: in (BL)
   abort                     @ 0x00007ffff7aa3862: in (BL)
   __sanitizer::Abort()      @ 0x00000000004b1937
   __sanitizer::Die()        @ 0x00000000004b0341
   ~ScopedInErrorReport      @ 0x0000000000499d69
   ReportGenericError        @ 0x000000000049926b
   __asan_report_load1       @ 0x0000000000499ee8
   op_recurse_ovecsave       @ 0x000000000055b80c
   match                     @ 0x0000000000525073
   match                     @ 0x0000000000541e67
   match                     @ 0x000000000051b9db
   match                     @ 0x0000000000549744
   match                     @ 0x0000000000541e67
   pcre2_match_8             @ 0x0000000000516392
   regexec                   @ 0x000000000056de11
   LLVMFuzzerTestOneInput    @ 0x00000000004c659d
```

```c
// pcre2_match.c, line 488, in function int op_recurse_ovecsave
do
  {
  if (cbegroup) mb->match_function_type = MATCH_CBEGROUP;
  rrc = match(eptr, callpat + PRIV(OP_lengths)[*callpat], mstart, offset_top, //When the crash is triggered, callpat = 221, so PRIV(OP_lengths)[*callpat] this array access is out of bounds. ( PRIV(OP_lengths) has the type const uint8_ t[164]）             
    mb, eptrb, rdepth + 1);
  memcpy(mb->ovector, new_recursive->ovec_save,
      mb->offset_end * sizeof(PCRE2_SIZE));
```

The official description of the bug is as follows. In the case of specific data, the code obtained after compiling pattern will be incorrect. The wrong code may cause heap overflow in the subsequent regular expression matching process.

> A pattern such as "((?+1)(\1))/" containing a forward reference subroutine call within a group that also contained a recursive back reference caused incorrect code to be compiled. This bug was reported as "heap overflow", discovered by Kai Lu of Fortinet's FortiGuard Labs.

See also  https://vcs.pcre.org/pcre2/code/trunk/src/pcre2_compile.c?r1=212&r2=211&pathrev=212 .

#### bug 5

```sh
__sanitizer::Abort() @ 0x00000000004b1937
Stack Head (13 entries):
   raise                     @ 0x00007ffff7ab9ef5: in (BL)
   abort                     @ 0x00007ffff7aa3862: in (BL)
   __sanitizer::Abort()      @ 0x00000000004b1937
   __sanitizer::Die()        @ 0x00000000004b0341
   ~ScopedInErrorReport      @ 0x0000000000499d69
   ReportGenericError        @ 0x000000000049926b
   __asan_report_store1      @ 0x000000000049a20b
   compile_branch            @ 0x00000000004ef556
   compile_regex             @ 0x00000000004d26e0
   pcre2_compile_8           @ 0x00000000004cfb97
   regcomp                   @ 0x000000000056d8d6
   LLVMFuzzerTestOneInput    @ 0x00000000004c6541
   main                      @ 0x000000000056eea7
```

```c
// pcre2_compile.c，6525, in function BOOL compile_branch.

*code++ = ((options & PCRE2_CASELESS) != 0)? OP_CHARI : OP_CHAR; // The *code here exceeds the allocated heap space.
```

The bug was fixed in SVN version 265. The official description of the bug is as follows:

> A recursive back reference by name within a group that had the same name as another group caused a buffer overflow. For example: /(?J)(?'d'(?'d'\g{d}))/. This bug was discovered by the LLVM fuzzer.

See also https://vcs.pcre.org/pcre2/code/trunk/src/pcre2_compile.c?r1=265&r2=264&pathrev=265.



#### bug 6

```sh
__sanitizer::Abort() @ 0x00000000004b1937
Stack Head (14 entries):
   raise                     @ 0x00007ffff7ab9ef5: in (BL)
   abort                     @ 0x00007ffff7aa3862: in (BL)
   __sanitizer::Abort()      @ 0x00000000004b1937
   __sanitizer::Die()        @ 0x00000000004b0341
   ~ScopedInErrorReport      @ 0x0000000000499d69
   ReportGenericError        @ 0x000000000049926b
   __asan_report_load1       @ 0x0000000000499ee8
   could_be_empty_branch     @ 0x00000000004d8890
   could_be_empty_branch     @ 0x00000000004d70b0
   could_be_empty_branch     @ 0x00000000004d70b0
   pcre2_compile_8           @ 0x00000000004d0ddf
   regcomp                   @ 0x000000000056d8d6
   LLVMFuzzerTestOneInput    @ 0x00000000004c6541
   main                      @ 0x000000000056eea7
```

Under some conditions, the program will determine the step size of character pointer movement by the content of string. At this time, an illegal data is injected into the content, which can make the moving step too long and lead to crossing.

```c
// pcre2_intmodedep.h, line 107
#define GET(a,n) \
  (((a)[n] << 8) | (a)[(n)+1]) //The macro returns an int value based on the content of the string.
```

```c
// pcre2_compile.c, line 1266

if (c == OP_BRAZERO || c == OP_BRAMINZERO || c == OP_SKIPZERO ||
    c == OP_BRAPOSZERO)
  {
  code += PRIV(OP_lengths)[c];
  do code += GET(code, 1); while (*code == OP_ALT); // Due to the specific content in the character pointer code, the return value of GET(code, 1) here is too large, causing beyond the boundary.
  c = *code;
  continue;
  }
```



#### bug 7

```sh
__sanitizer::Abort() @ 0x00000000004b1937
Stack Head (16 entries):
   raise                     @ 0x00007ffff7ab9ef5: in (BL)
   abort                     @ 0x00007ffff7aa3862: in (BL)
   __sanitizer::Abort()      @ 0x00000000004b1937
   __sanitizer::Die()        @ 0x00000000004b0341
   ~ScopedInErrorReport      @ 0x0000000000499d69
   ReportGenericError        @ 0x000000000049926b
   __asan_report_store1      @ 0x000000000049a20b
   add_to_class              @ 0x00000000004f44d4
   add_list_to_class         @ 0x00000000004f4008
   add_to_class              @ 0x00000000004f4008
   compile_branch            @ 0x00000000004df57d
   compile_regex             @ 0x00000000004d26e0
   pcre2_compile_8           @ 0x00000000004cfb97
   regcomp                   @ 0x000000000056d8d6
   LLVMFuzzerTestOneInput    @ 0x00000000004c6541
   main                      @ 0x000000000056eea7
```

```c
  // pcre2_compile.c, line 2856, in function add_to_class
  
  PCRE2_UCHAR *uchardata = *uchardptr;

#ifdef SUPPORT_UNICODE
  if ((options & PCRE2_UTF) != 0)
    {
    if (start < end)
      {
      *uchardata++ = XCL_RANGE; // Here *uchardata is out of bounds. The reason is that the space allocated by uchardata is calculated incorrectly and is too small.
      uchardata += PRIV(ord2utf)(start, uchardata);
      uchardata += PRIV(ord2utf)(end, uchardata);
      }
```

The official description of the bug is as follows. That is to say, some special character combinations will cause the program to calculate the space that needs to be allocated wrongly, resulting in insufficient space allocated and causing out of bounds write in subsequent calculation.

> A pattern such as /(*UTF)[\S\V\H]/, which contains a negated special class such as \S in non-UCP mode, explicit wide characters (> 255) can be ignored because \S ensures they are all in the class. The code for doing this was interacting badly with the code for computing the amount of space needed to compile the pattern, leading to a buffer overflow. This bug was discovered by the LLVM fuzzer.

See also  https://vcs.pcre.org/pcre2/code/trunk/src/pcre2_compile.c?r1=232&r2=233.

#### bug 8

```sh
__sanitizer::Abort() @ 0x00000000004b1937
Stack Head (18 entries):
   raise                     @ 0x00007ffff7ab9ef5: in (BL)
   abort                     @ 0x00007ffff7aa3862: in (BL)
   __sanitizer::Abort()      @ 0x00000000004b1937
   __sanitizer::Die()        @ 0x00000000004b0341
   ~ScopedInErrorReport      @ 0x0000000000499d69
   ReportGenericError        @ 0x000000000049926b
   __asan_report_store1      @ 0x000000000049a20b
   _pcre2_ord2utf_8          @ 0x000000000055de59
   add_to_class              @ 0x00000000004f4322
   add_list_to_class         @ 0x00000000004f4008
   add_to_class              @ 0x00000000004f4008
   add_not_list_to_class     @ 0x00000000004e18a4
   compile_branch            @ 0x00000000004e18a4
   compile_regex             @ 0x00000000004d26e0
   pcre2_compile_8           @ 0x00000000004cfb97
   regcomp                   @ 0x000000000056d8d6
```

```c
// pcre2_ord2utf.c, line 80
unsigned int
PRIV(ord2utf)(uint32_t cvalue, PCRE2_UCHAR *buffer)
{
...
for (j = i; j > 0; j--)
 {
 *buffer-- = 0x80 | (cvalue & 0x3f); // Here *buffer triggers one byte out of bounds write.
 cvalue >>= 6;
 }
    

// The function above is called in add_to_class：
// pcre2_compile.c, line 2865, in function add_to_class
    uchardata += PRIV(ord2utf)(end, uchardata); // The `uchardata` here corresponds to the `buffer` variable above. Like bug 7, the allocated space is too small, causing an out of bounds write at the function above
```



#### bug 9

```sh
__sanitizer::Abort() @ 0x00000000004b1937
Stack Head (12 entries):
   raise                     @ 0x00007ffff7ab9ef5: in (BL)
   abort                     @ 0x00007ffff7aa3862: in (BL)
   __sanitizer::Abort()      @ 0x00000000004b1937
   __sanitizer::Die()        @ 0x00000000004b0341
   ~ScopedInErrorReport      @ 0x0000000000499d69
   ReportGenericError        @ 0x000000000049926b
   __asan_report_load1       @ 0x0000000000499ee8
   _pcre2_find_bracket_8     @ 0x00000000004cd7f7
   pcre2_compile_8           @ 0x00000000004d01b8
   regcomp                   @ 0x000000000056d8d6
   LLVMFuzzerTestOneInput    @ 0x00000000004c6541
   main                      @ 0x000000000056eea7
```

```c
// pcre2_compile.c, line 2254
PCRE2_SPTR
PRIV(find_bracket)(PCRE2_SPTR code, BOOL utf, int number)
{
  for (;;)
  {
    register PCRE2_UCHAR c = *code;
    ...
    code += PRIV(OP_lengths)[c]; //PRIV(OP_lengths) is an array named _pcre2_OP_lengths_8, type is const uint8_ t[164]。
	// For the input that causes a crash, here c = 189, which results in an out of bounds access to the array.
```

#### bug 10

```sh
__sanitizer::Abort() @ 0x00000000004b1937
Stack Head (13 entries):
   raise                     @ 0x00007ffff7ab9ef5: in (BL)
   abort                     @ 0x00007ffff7aa3862: in (BL)
   __sanitizer::Abort()      @ 0x00000000004b1937
   __sanitizer::Die()        @ 0x00000000004b0341
   ~ScopedInErrorReport      @ 0x0000000000499d69
   ReportGenericError        @ 0x000000000049926b
   __asan_report_load1       @ 0x0000000000499ee8
   is_startline              @ 0x00000000004d6a28
   is_startline              @ 0x00000000004d62a2
   pcre2_compile_8           @ 0x00000000004d0b55
   regcomp                   @ 0x000000000056d8d6
   LLVMFuzzerTestOneInput    @ 0x00000000004c6541
   main                      @ 0x000000000056eea7
```

The official description of the bug is as follows：

> If an assertion that was used as a condition was quantified with a minimum of zero, matching went wrong. In particular, if the whole group had unlimited repetition and could match an empty string, a segfault was likely. The pattern (?(?=0)?)+ is an example that caused this. Perl allows assertions to be quantified, but not if they are being used as conditions, so the above pattern is faulted by Perl. PCRE2 has now been changed so that it also rejects such patterns

For the repair code, see https://vcs.pcre.org/pcre2/code/trunk/src/pcre2_compile.c?r1=189&r2=190。 The method is to introduce a variable `iscondassert` to judge whether the assert is a condition, update the variable during the operation and use it to avoid unlimited repetition.

#### bug 11

```sh
__sanitizer::Abort() @ 0x00000000004b1937
Stack Head (14 entries):
   raise                     @ 0x00007ffff7ab9ef5: in (BL)
   abort                     @ 0x00007ffff7aa3862: in (BL)
   __sanitizer::Abort()      @ 0x00000000004b1937
   __sanitizer::Die()        @ 0x00000000004b0341
   ~ScopedInErrorReport      @ 0x0000000000499d69
   ReportGenericError        @ 0x000000000049926b
   __asan_report_load1       @ 0x0000000000499ee8
   compare_opcodes           @ 0x00000000004cced9
   compare_opcodes           @ 0x00000000004c99f5
   _pcre2_auto_possessify_8  @ 0x00000000004c6e73
   pcre2_compile_8           @ 0x00000000004d031a
   regcomp                   @ 0x000000000056d8d6
   LLVMFuzzerTestOneInput    @ 0x00000000004c6541
   main                      @ 0x000000000056eea7
```

```c
// pcre2_auto_possess.c, line 669, in function BOOL compare_opcodes
	if (*next_code != OP_BRA && *next_code != OP_CBRA
        && *next_code != OP_ONCE && *next_code != OP_ONCE_NC) return FALSE;

    do next_code += GET(next_code, 1); while (*next_code == OP_ALT);//GET(next_code, 1) is too large, next_code is read after moving the corresponding step size, resulting in Heap Buffer overflow
```



#### bug 12

```sh
__sanitizer::Abort() @ 0x00000000004b1937
Stack Head (12 entries):
   raise                     @ 0x00007ffff7ab9ef5: in (BL)
   abort                     @ 0x00007ffff7aa3862: in (BL)
   __sanitizer::Abort()      @ 0x00000000004b1937
   __sanitizer::Die()        @ 0x00000000004b0341
   ~ScopedInErrorReport      @ 0x0000000000499d69
   ReportGenericError        @ 0x000000000049926b
   __asan_report_store1      @ 0x000000000049a20b
   compile_regex             @ 0x00000000004d3881
   pcre2_compile_8           @ 0x00000000004cfb97
   regcomp                   @ 0x000000000056d8d6
   LLVMFuzzerTestOneInput    @ 0x00000000004c6541
   main                      @ 0x000000000056eea7
```
```c
// pcre2_compile.c, line 6855, in function BOOL compile_regex
	*code = OP_KET; // Crash raised here
    PUT(code, 1, (int)(code - start_bracket));
    code += 1 + LINK_SIZE;
```

This is due to the calculation error of allocation space. As a result, the actual write size to the code is larger than the allocated space. The official description of the bug is as follows:

> If a bug that caused pcre2_compile() to use more memory than allocated was triggered when using valgrind, the code in (3) above passed a stupidly large value to valgrind. This caused a crash instead of an "internal error" return.  \7. A reference to a duplicated named group (either a back reference or a test for being set in a conditional) that occurred in a part of the pattern where PCRE2_DUPNAMES was not set caused the amount of memory needed for the pattern to be incorrectly calculated, leading to overwriting.

See also https://vcs.pcre.org/pcre2/code/trunk/src/pcre2_compile.c?r1=187&r2=188.

### re2

#### bug 1
```sh
__sanitizer::Abort() @ 0x00000000004b2ac7
Stack Head (14 entries):
   raise                     @ 0x00007ffff7ab9ef5: in (BL)
   abort                     @ 0x00007ffff7aa3862: in (BL)
   __sanitizer::Abort()      @ 0x00000000004b2ac7
   __sanitizer::Die()        @ 0x00000000004b14d1
   ~ScopedInErrorReport      @ 0x000000000049aef9
   ReportGenericError        @ 0x000000000049a3fb
   __asan_report_store8      @ 0x000000000049b5db
   Search                    @ 0x00000000005302a9
   SearchNFA                 @ 0x0000000000532c8a
   Match                     @ 0x00000000004d3e2f
   DoMatch                   @ 0x00000000004cf136
   operator()                @ 0x00000000004c78f6
   LLVMFuzzerTestOneInput    @ 0x00000000004c78f6
   main                      @ 0x000000000055e607
```

Array cross boundary access. The reason is that the code does not judge whether the index exceeds the length of the array.

```c
// nfa.cc, line 446
  match_ = new const char*[ncapture_]; 
// The space assigned to match_ is ncapture_*sizeof(const char *). For crash file as the input, ncapture_= 2.
  matched_ = false;
  memset(match_, 0, ncapture_*sizeof match_[0]);
```

```c
// nfa.cc, line 531
case kInstCapture:
  match_[ip->cap()] = p; // Not judge whether ip->cap() exceeds ncapture_. For crash file as the input, ip->cap() = 3, causes out of boundary.
//In the later fix code, `if (ip->cap() < ncapture_) ` is added to determine whether it is out of bounds.
  id = ip->out();
  continue;
```

### woff2

The calculation error of the space to be allocated to the array results in the cross-border access in the subsequent operation.

```sh
__sanitizer::Abort() @ 0x00000000004b1f67
Stack Head (13 entries):
   raise                     @ 0x00007ffff7ab9ef5: in (BL)
   abort                     @ 0x00007ffff7aa3862: in (BL)
   __sanitizer::Abort()      @ 0x00000000004b1f67
   __sanitizer::Die()        @ 0x00000000004b0971
   ~ScopedInErrorReport      @ 0x000000000049a399
   ReportGenericError        @ 0x000000000049989b
   __asan_memcpy             @ 0x0000000000493b02
   Read                      @ 0x00000000005de5aa
   ReconstructGlyf           @ 0x00000000005de5aa
   ReconstructFont           @ 0x00000000005de5aa
   ConvertWOFF2ToTTF         @ 0x00000000005de5aa
   LLVMFuzzerTestOneInput    @ 0x00000000005f4942
   main                      @ 0x00000000005f3757
```

```c
// woff2_dec.cc, line 481, in function ReconstructGlyf
size_t size_needed = 2 + composite_size + instruction_size; // Too little space allocated here. The subsequent repair code is changed to `12 + composite_size + instruction_size`。
if (PREDICT_FALSE(glyph_buf_size < size_needed)) {
  glyph_buf.reset(new uint8_t[size_needed]);
  glyph_buf_size = size_needed;
}
...

    // line 500
        if (PREDICT_FALSE(!instruction_stream.Read(glyph_buf.get() + glyph_size,  // In the input that causes the crash, where glyph_size = 26, composite_size = 14, so this location will have 26 - 14 - 2 = 10 bytes out of bounds.                                                   
              instruction_size))) {
          return FONT_COMPRESSION_FAILURE();
        }
...

// Read is defined as follows， buffer.h, line 77
  bool Read(uint8_t *buffer, size_t n_bytes) {
    if (n_bytes > 1024 * 1024 * 1024) {
      return FONT_COMPRESSION_FAILURE();
    }
    if ((offset_ + n_bytes > length_) ||
        (offset_ > length_ - n_bytes)) {
      return FONT_COMPRESSION_FAILURE();
    }
    if (buffer) {
      std::memcpy(buffer, buffer_ + offset_, n_bytes); // Because of the above cross-border access, the memcpy here triggers asan.
    }
    offset_ += n_bytes;
    return true;
  }
```

The fixed code could be found in https://chromium.googlesource.com/chromium/src.git/+/d6fdbb084660f06781c6932cc44b09aca20dfa29.





**More bugs could be found in continuous fuzzing.**

### guetzli

#### Bug 2

When the log2floornonzero function runs with (int16_t) -32768, it will be converted to unsigned, resulting in larger results. These results are used to access the subscript of the array, and an exception is thrown.

```cpp
// fast_log.h, line 24

inline int Log2FloorNonZero(uint32_t n) { //A small negative number is encountered and becomes an unsigned integer of level 2 ^ 32
#ifdef __GNUC__
  return 31 ^ __builtin_clz(n);
#else
  unsigned int result = 0;
  while (n >>= 1) result++;
  return result; // //Returning to 31, the number is obviously too large
#endif
}
```

```cpp
// jpeg_data_writer.cc, line 491

int nbits = Log2FloorNonZero(temp) + 1; // Constructing special data makes temp = - 32768, but the result nbits of log2 is wrongly calculated as 32, which is the cause of crash.
int symbol = (r << 4) + nbits; // r = 15, nbits = 32. symbol = 272
bw->WriteBits(ac_huff.depth[symbol], ac_huff.code[symbol]); // The array size of depth and code is only 256, causing Heap Buffer overflow
bw->WriteBits(nbits, temp2 & ((1 << nbits) - 1));
r = 0;
```

### harfbuzz

An assert is triggered.

```cpp
end = int (end) + delta;
if (end <= match_positions[idx])
{

  assert (end == match_positions[idx]);
  break;
}
```

### libarchive

```cpp
// libarchive_fuzzer.cc

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  ssize_t r;
  struct archive *a = archive_read_new();

  archive_read_support_filter_all(a);
  archive_read_support_format_all(a);

  Buffer buffer = {buf, len}; // Wrong use the buf array as a string array
  archive_read_open(a, &buffer, NULL, reader_callback, NULL);
  
  ...
      

// Where the crash happend, archive_read_support_format_warc.c, line 537
    while (isspace((unsigned char)*s))  // Because the previous input is not a string array, when reading s [len] after reading all non-zero data, it will cause 1 byte out of bounds.
        ++s;
```

### pcre2

#### bug 13

```sh
__sanitizer::Abort() @ 0x00000000004b1937
Stack Head (15 entries):
   raise                     @ 0x00007ffff7ab9ef5: in (BL)
   abort                     @ 0x00007ffff7aa3862: in (BL)
   __sanitizer::Abort()      @ 0x00000000004b1937
   __sanitizer::Die()        @ 0x00000000004b0341
   ~ScopedInErrorReport      @ 0x0000000000499d69
   ReportGenericError        @ 0x000000000049926b
   __asan_report_load1       @ 0x0000000000499ee8
   first_significant_code    @ 0x00000000004d87a7
   could_be_empty_branch     @ 0x00000000004d87a7
   could_be_empty_branch     @ 0x00000000004d70b0
   could_be_empty_branch     @ 0x00000000004d70b0
   pcre2_compile_8           @ 0x00000000004d0ddf
   regcomp                   @ 0x000000000056d8d6
   LLVMFuzzerTestOneInput    @ 0x00000000004c6541
   main                      @ 0x000000000056eea7
```

#### bug 14

```sh
__sanitizer::Abort() @ 0x00000000004b1937
Stack Head (8 entries):
   raise                     @ 0x00007ffff7ab9ef5: in (BL)
   abort                     @ 0x00007ffff7aa3862: in (BL)
   __sanitizer::Abort()      @ 0x00000000004b1937
   __sanitizer::Die()        @ 0x00000000004b0341
   CheckForLeaks             @ 0x00000000004baee4
   DoLeakCheck               @ 0x00000000004bab72
   __run_exit_handlers       @ 0x00007ffff7abc697: in (BL)
   exit                      @ 0x00007ffff7abc83e: in (BL)
```

#### bug 15

```sh
_pcre2_xclass_8 @ 0x000000000056b3ce
Stack Head (7 entries):
   _pcre2_xclass_8           @ 0x000000000056b3ce
   match                     @ 0x000000000052aaa4
   match                     @ 0x000000000054361a
   pcre2_match_8             @ 0x0000000000516392
   regexec                   @ 0x000000000056de11
   LLVMFuzzerTestOneInput    @ 0x00000000004c659d
   main                      @ 0x000000000056eea7
```

### re2

#### bug 2

```sh
__sanitizer::Abort() @ 0x00000000004b2ac7
Stack Head (8 entries):
   raise                     @ 0x00007ffff7ab9ef5: in (BL)
   abort                     @ 0x00007ffff7aa3862: in (BL)
   __sanitizer::Abort()      @ 0x00000000004b2ac7
   __sanitizer::Die()        @ 0x00000000004b14d1
   CheckForLeaks             @ 0x00000000004bc074
   DoLeakCheck               @ 0x00000000004bbd02
   __run_exit_handlers       @ 0x00007ffff7abc697: in (BL)
   exit                      @ 0x00007ffff7abc83e: in (BL)
```

### vorbis

```c
// codebook.c, line 396
long vorbis_book_decodev_add(codebook *book,float *a,oggpack_buffer *b,int n){
  if(book->used_entries>0){
    int i,j,entry;
    float *t;

    if(book->dim>8){
        for(i=0;i<n;){
          entry = decode_packed_entry_number(book,b);
          if(entry==-1)return(-1);
          t     = book->valuelist+entry*book->dim;
          for (j=0;j<book->dim;)
            a[i++]+=t[j++]; // Whether i is less than n is not judged here, and a boundary crossing is triggered under specific data. Later fix code wrote i < n into the loop condition.
        }
```

