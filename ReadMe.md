# Byte Packed Password

This library provides various functions to work with passwords packed into 
bytes.

Among them are functions:
* to pack symbols into bytes; 
* to unpack symbols from bytes; 
* to hash a password with salt into a key; 
* to hash a password with salt and compare it with another key; 
* to generate a random salt for a password.

Hashing algorithm is _Argon2_ in general and _Argon2id_ in particular.  
Settings of hashing are hard-coded into the library.  
_Argon2_ algorithm was selected as the winner of the 2015 Password Hashing 
Competition.

## Allowed ASCII symbols

Allowed password symbols include all 64 symbols of the range from 0x20 (32, 
White Space) to 0x5F (95, Low Line).

Passwords may contain following _ASCII_ symbols:
* 10 number symbols from 0 to 9
* 26 latin capital letters from A to Z
* 28 special symbols

28 allowed special (i.e. non-alphanumeric) symbols are listed below:

| Symbol | Description              |
|:------:|--------------------------|
|        | White Space              |
|   !    | Exclamation mark         |
|   "    | Quotation mark           |
|   #    | Number sign              |
|   $    | Dollar sign              |
|   %    | Percent sign             |
|   &    | Ampersand                |
|   '    | Apostrophe               |
|   (    | Left parenthesis         |
|   )    | Right parenthesis        |
|   *    | Asterisk                 |
|   +    | Plus sign                |
|   ,    | Comma                    |
|   -    | Hyphen-minus             |
|   .    | Full stop or period      |
|   /    | Solidus or Slash         |
|   :    | Colon                    |
|   ;    | Semicolon                |
|  &lt;  | Less-than sign           |
|   =    | Equal sign               |
|  &gt;  | Greater-than sign        |
|   ?    | Question mark            |
|   @    | At sign or Commercial at |
|   [    | Left Square Bracket      |
|   \    | Backslash                |
|   ]    | Right Square Bracket     |
|   ^    | Circumflex accent        |
|   _    | Low line                 |

Password length must be a multiple of four due to technical limitations.  
Minimal password length is 16 symbols.

More information about _ASCII_ can be found in the Internet:  
https://en.wikipedia.org/wiki/ASCII

Basic latin segment of the _Unicode_ is described here:  
https://en.wikipedia.org/wiki/Basic_Latin_(Unicode_block)

## Configuration

This library uses constant settings while the _Argon 2_ algorithm is highly 
dependent on all the settings.  
The used settings are following.

| Setting             | Value                      |
|---------------------|----------------------------|
| Memory usage        | 8 MiB, i.e. 8192 Kibibytes |
| Threads             | 1                          |
| Iterations (passes) | 8                          |
| Salt length         | 1024                       |
| Key length          | 1024                       |
