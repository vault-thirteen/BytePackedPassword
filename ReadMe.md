# Byte Packed Password

This library provides various functions to work with passwords packed into 
bytes.

Among them are functions:
* to pack symbols into bytes; 
* to unpack bytes into symbols; 
* to hash a password with salt into a key; 
* to hash a password with salt and compare it with another key; 
* to generate a random salt for a password.

Hashing algorithm is Argon2 in general and Argon2id in particular.  
Settings of hashing are hard-coded into the library.  
Argon2 algorithm was selected as the winner of the 2015 Password Hashing 
Competition.

Allowed password symbols include all 64 symbols of the range from 0x20 (32, 
White Space) to 0x5F (95, Low Line).

Passwords may contain following ASCII symbols:
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

More information about ASCII can be found in the Internet:  
https://en.wikipedia.org/wiki/ASCII

Basic latin segment of the Unicode is described here:  
https://en.wikipedia.org/wiki/Basic_Latin_(Unicode_block)

