<?php
global $BEAUT_PATH;
if (!isset ($BEAUT_PATH)) return;
require_once("$BEAUT_PATH/Beautifier/HFile.php");
  class HFile_fortran90 extends HFile{
   function HFile_fortran90(){
     $this->HFile();	
/*************************************/
// Beautifier Highlighting Configuration File 
// Fortran 90
/*************************************/
// Flags

$this->nocase            	= "1";
$this->notrim            	= "0";
$this->perl              	= "0";

// Colours

$this->colours        	= array("blue", "brown", "purple", "gray", "blue", "purple", "gray");
$this->quotecolour       	= "blue";
$this->blockcommentcolour	= "green";
$this->linecommentcolour 	= "green";

// Indent Strings

$this->indent            	= array("THEN", "ELSE", "DO", "FORALL");
$this->unindent          	= array("ENDIF", "ENDDO", "END IF", "END DO");

// String characters and delimiters

$this->stringchars       	= array("\"", "'");
$this->delimiters        	= array("~", "!", "@", "%", "^", "&", "*", "(", ")", "-", "+", "=", "|", "\\", "/", "{", "}", "[", "]", ":", ";", "\"", "'", "<", ">", " ", ",");
$this->escchar           	= "";

// Comment settings

$this->linecommenton     	= array("! $");
$this->blockcommenton    	= array("");
$this->blockcommentoff   	= array("");

// Keywords (keyword mapping to colour number)

$this->keywords          	= array(
			"ADMIT" => "1", 
			"ALLOCATABLE" => "1", 
			"ALLOCATE" => "1", 
			"ASSIGN" => "4", 
			"ASSIGNMENT" => "1", 
			"AT" => "1", 
			"BACKSPACE" => "4", 
			"BLOCK" => "1", 
			"CALL" => "1", 
			"CASE" => "1", 
			"CHARACTER" => "1", 
			"CLOSE" => "4", 
			"COMMON" => "1", 
			"COMPLEX" => "1", 
			"CONTAINS" => "1", 
			"CONTINUE" => "1", 
			"CYCLE" => "1", 
			"DATA" => "1", 
			"DEALLOCATE" => "1", 
			"DEFAULT" => "1", 
			"DIMENSION" => "1", 
			"DO" => "1", 
			"DOUBLE" => "1", 
			"ELSE" => "1", 
			"ELSEIF" => "1", 
			"ELSEWHERE" => "1", 
			"END" => "1", 
			"ENDDO" => "1", 
			"ENDFILE" => "4", 
			"ENDIF" => "1", 
			"ENDWHILE" => "1", 
			"ENTRY" => "1", 
			"EQUIVALENCE" => "1", 
			"EXECUTE" => "1", 
			"EXIT" => "1", 
			"EXTERNAL" => "1", 
			"FORALL" => "1", 
			"FORMAT" => "1", 
			"FUNCTION" => "1", 
			"GO" => "1", 
			"GOTO" => "1", 
			"GUESS" => "1", 
			"IF" => "1", 
			"IMPLICIT" => "1", 
			"IN" => "1", 
			"INOUT" => "1", 
			"INQUIRE" => "1", 
			"INTEGER" => "1", 
			"INTENT" => "1", 
			"INTERFACE" => "1", 
			"INTRINSIC" => "1", 
			"KIND" => "1", 
			"LOGICAL" => "1", 
			"LOOP" => "1", 
			"MAP" => "1", 
			"MODULE" => "1", 
			"NAMELIST" => "1", 
			"NONE" => "1", 
			"NULLIFY" => "1", 
			"ONLY" => "1", 
			"OPEN" => "4", 
			"OPERATOR" => "1", 
			"OPTIONAL" => "1", 
			"OTHERWISE" => "1", 
			"OUT" => "1", 
			"PARAMETER" => "1", 
			"POINTER" => "1", 
			"PRIVATE" => "1", 
			"PROCEDURE" => "1", 
			"PROGRAM" => "1", 
			"PUBLIC" => "1", 
			"QUIT" => "1", 
			"READ" => "4", 
			"REAL" => "1", 
			"RECORD" => "1", 
			"RECURSIVE" => "1", 
			"REMOTE" => "1", 
			"RESULT" => "1", 
			"RETURN" => "1", 
			"REWIND" => "4", 
			"SAVE" => "1", 
			"SELECT" => "1", 
			"SEQUENCE" => "1", 
			"STOP" => "1", 
			"STRUCTURE" => "1", 
			"SUBROUTINE" => "1", 
			"TARGET" => "1", 
			"THEN" => "1", 
			"TO" => "1", 
			"TYPE" => "1", 
			"UNION" => "1", 
			"UNTIL" => "1", 
			"USE" => "1", 
			"WHERE" => "1", 
			"WHILE" => "1", 
			"WRITE" => "4", 
			".AND." => "2", 
			".EQ." => "2", 
			".EQV." => "2", 
			".GE." => "2", 
			".GT." => "2", 
			".LE." => "2", 
			".LT." => "2", 
			".NE." => "2", 
			".NEQV." => "2", 
			".NOT." => "2", 
			".OR." => "2", 
			"ABS" => "3", 
			"ACHAR" => "3", 
			"ACOS" => "3", 
			"ADJUSTL" => "3", 
			"ADJUSTR" => "3", 
			"AIMAG" => "3", 
			"AINT" => "3", 
			"ALL" => "3", 
			"ALLOCATED" => "3", 
			"ANINT" => "3", 
			"ANY" => "3", 
			"ASIN" => "3", 
			"ASSOCIATED" => "3", 
			"ATAN" => "3", 
			"ATAN2" => "3", 
			"BIT_SIZE" => "3", 
			"BREAK" => "3", 
			"BTEST" => "3", 
			"CARG" => "3", 
			"CEILING" => "3", 
			"CHAR" => "3", 
			"CMPLX" => "3", 
			"CONJG" => "3", 
			"COS" => "3", 
			"COSH" => "3", 
			"COUNT" => "3", 
			"CSHIFT" => "3", 
			"DATE_AND_TIME" => "3", 
			"DBLE" => "3", 
			"DIGITS" => "3", 
			"DIM" => "3", 
			"DOT_PRODUCT" => "3", 
			"DPROD" => "3", 
			"DVCHK" => "3", 
			"EOSHIFT" => "3", 
			"EPSILON" => "3", 
			"ERROR" => "3", 
			"EXP" => "3", 
			"EXPONENT" => "3", 
			"FLOOR" => "3", 
			"FLUSH" => "3", 
			"FRACTION" => "3", 
			"GETCL" => "3", 
			"HUGE" => "3", 
			"IACHAR" => "3", 
			"IAND" => "3", 
			"IBCLR" => "3", 
			"IBITS" => "3", 
			"IBSET" => "3", 
			"ICHAR" => "3", 
			"IEOR" => "3", 
			"INDEX" => "3", 
			"INT" => "3", 
			"INTRUP" => "3", 
			"INVALOP" => "3", 
			"IOR" => "3", 
			"IOSTAT_MSG" => "3", 
			"ISHFT" => "3", 
			"ISHFTC" => "3", 
			"LBOUND" => "3", 
			"LEN" => "3", 
			"LEN_TRIM" => "3", 
			"LGE" => "3", 
			"LGT" => "3", 
			"LLE" => "3", 
			"LLT" => "3", 
			"LOG" => "3", 
			"LOG10" => "3", 
			"MATMUL" => "3", 
			"MAX" => "3", 
			"MAXEXPONENT" => "3", 
			"MAXLOC" => "3", 
			"MAXVAL" => "3", 
			"MERGE" => "3", 
			"MIN" => "3", 
			"MINEXPONENT" => "3", 
			"MINLOC" => "3", 
			"MINVAL" => "3", 
			"MOD" => "3", 
			"MODULO" => "3", 
			"MVBITS" => "3", 
			"NBREAK" => "3", 
			"NDPERR" => "3", 
			"NDPEXC" => "3", 
			"NEAREST" => "3", 
			"NINT" => "3", 
			"NOT" => "3", 
			"OFFSET" => "3", 
			"OVEFL" => "3", 
			"PACK" => "3", 
			"PRECFILL" => "3", 
			"PRECISION" => "3", 
			"PRESENT" => "3", 
			"PRODUCT" => "3", 
			"PROMPT" => "3", 
			"RADIX" => "3", 
			"RANDOM_NUMBER" => "3", 
			"RANDOM_SEED" => "3", 
			"RANGE" => "3", 
			"REPEAT" => "3", 
			"RESHAPE" => "3", 
			"RRSPACING" => "3", 
			"SCALE" => "3", 
			"SCAN" => "3", 
			"SEGMENT" => "3", 
			"SELECTED_INT_KIND" => "3", 
			"SELECTED_REAL_KIND" => "3", 
			"SET_EXPONENT" => "3", 
			"SHAPE" => "3", 
			"SIGN" => "3", 
			"SIN" => "3", 
			"SINH" => "3", 
			"SIZE" => "3", 
			"SPACING" => "3", 
			"SPREAD" => "3", 
			"SQRT" => "3", 
			"SUM" => "3", 
			"SYSTEM" => "3", 
			"SYSTEM_CLOCK" => "3", 
			"TAN" => "3", 
			"TANH" => "3", 
			"TIMER" => "3", 
			"TINY" => "3", 
			"TRANSFER" => "3", 
			"TRANSPOSE" => "3", 
			"TRIM" => "3", 
			"UBOUND" => "3", 
			"UNDFL" => "3", 
			"UNPACK" => "3", 
			"VAL" => "3", 
			"VERIFY" => "3", 
			"PAUSE" => "4", 
			"PRINT" => "4", 
			"ACCESS" => "5", 
			"ACTION" => "5", 
			"BLANK" => "5", 
			"BLOCKSIZE" => "5", 
			"CARRIAGECONTROL" => "5", 
			"DIRECT" => "5", 
			"ERR" => "5", 
			"EXIST" => "5", 
			"FILE" => "5", 
			"FMT" => "5", 
			"FORM" => "5", 
			"FORMATTED" => "5", 
			"FROM" => "5", 
			"IOSTAT" => "5", 
			"LOCATION" => "5", 
			"NAME" => "5", 
			"NAMED" => "5", 
			"NEXTREC" => "5", 
			"NUMBER" => "5", 
			"OPENED" => "5", 
			"POSITION" => "5", 
			"RECL" => "5", 
			"RECORDTYPE" => "5", 
			"SEQUENTIAL" => "5", 
			"STAT" => "5", 
			"STATUS" => "5", 
			"UNFORMATTED" => "5", 
			"UNIT" => "5", 
			"INCLUDE" => "6", 
			"==" => "7", 
			"=" => "7", 
			"<" => "7", 
			">" => "7", 
			"+" => "7", 
			"*" => "7", 
			"^" => "7", 
			"-" => "7", 
			"//" => "7", 
			"/" => "7", 
			"!" => "7", 
			"&" => "7");

// Special extensions

// Each category can specify a PHP function that returns an altered
// version of the keyword.
        
        

$this->linkscripts    	= array(
			"1" => "donothing", 
			"4" => "donothing", 
			"2" => "donothing", 
			"3" => "donothing", 
			"5" => "donothing", 
			"6" => "donothing", 
			"7" => "donothing");
}


function donothing($keywordin)
{
	return $keywordin;
}

}?>
