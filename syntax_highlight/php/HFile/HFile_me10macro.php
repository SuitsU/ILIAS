<?php
global $BEAUT_PATH;
if (!isset ($BEAUT_PATH)) return;
require_once("$BEAUT_PATH/Beautifier/HFile.php");
  class HFile_me10macro extends HFile{
   function HFile_me10macro(){
     $this->HFile();	
/*************************************/
// Beautifier Highlighting Configuration File 
// ME10 Macro
/*************************************/
// Flags

$this->nocase            	= "1";
$this->notrim            	= "0";
$this->perl              	= "0";

// Colours

$this->colours        	= array("brown", "blue");
$this->quotecolour       	= "blue";
$this->blockcommentcolour	= "green";
$this->linecommentcolour 	= "green";

// Indent Strings

$this->indent            	= array();
$this->unindent          	= array();

// String characters and delimiters

$this->stringchars       	= array("\"", "'");
$this->delimiters        	= array("~", "!", "@", "%", "^", "&", "*", "(", ")", "-", "+", "=", "|", "\\", "/", "[", "]", ":", ";", "\"", "'", "<", ">", " ", ",", "	", ".", "?");
$this->escchar           	= "";

// Comment settings

$this->linecommenton     	= array("");
$this->blockcommenton    	= array("{");
$this->blockcommentoff   	= array("}");

// Keywords (keyword mapping to colour number)

$this->keywords          	= array(
			"/Indent" => "", 
			"Strings" => "", 
			"=" => "4", 
			"/Unindent" => "", 
			"ABOVE" => "1", 
			"ABS" => "1", 
			"ABSOLUTE" => "1", 
			"ACCESS_MELS" => "1", 
			"ACCESS_MELS_FREE_LICENSE" => "1", 
			"ADD" => "1", 
			"ADD_CURRENT_INFO" => "1", 
			"ADD_CURRENT_URL" => "1", 
			"ADD_DIM_POSTFIX" => "1", 
			"ADD_DIM_PREFIX" => "1", 
			"ADD_DIM_SUBFIX" => "1", 
			"ADD_DIM_SUPERFIX" => "1", 
			"ADD_DIM_TOLERANCE" => "1", 
			"ADD_ELEM_INFO" => "1", 
			"ADD_ELEM_URL" => "1", 
			"ADD_PART_URL" => "1", 
			"ADJACENT_NEG" => "1", 
			"ADJACENT_POS" => "1", 
			"ADU_ACCURACY" => "1", 
			"ADU_ATTACH_ANNOS" => "1", 
			"ADU_ATTACH_IDMAP" => "1", 
			"ADU_CHECK" => "1", 
			"ADU_CHECK_VIEW_POSITIONS" => "1", 
			"ADU_CONFIRM_ANNOS" => "1", 
			"ADU_DELETE_REGENERATED_GEO" => "1", 
			"ADU_GATHER_3D_PARTS_UNDER_2D_PARTS" => "1", 
			"ADU_MASTER_FOR_3D_HATCHES" => "1", 
			"ADU_MASTER_FOR_GEOMETRY_ATTRIBUTES" => "1", 
			"ADU_MASTER_FOR_PARTNAMES" => "1", 
			"ADU_RESULT" => "1", 
			"ADU_UPDATE_ANNOS" => "1", 
			"AFFINE" => "1", 
			"ALIGN" => "1", 
			"ALIGN_OFF" => "1", 
			"ALIGN_ON" => "1", 
			"ALL" => "1", 
			"ALLTYPES" => "1", 
			"ALL_ABOVE" => "1", 
			"ALL_ACTIVE" => "1", 
			"ALL_BELOW" => "1", 
			"ALL_VISIBLE" => "1", 
			"ALT" => "1", 
			"ALT_CONTROL" => "1", 
			"ANALYZE_BSPLINE" => "1", 
			"AND" => "1", 
			"ANG" => "1", 
			"ANGLE_PAR" => "1", 
			"ANGLE_TO" => "1", 
			"ANG_BISECT" => "1", 
			"ANSI" => "1", 
			"ANY" => "1", 
			"APPEND" => "1", 
			"APPEND_STRING" => "1", 
			"APPROVE" => "1", 
			"ARC" => "1", 
			"ARCCOS" => "1", 
			"ARCS" => "1", 
			"ARCSIN" => "1", 
			"ARCTAN" => "1", 
			"ARC_DIMS" => "1", 
			"ARC_RESOLUTION" => "1", 
			"AREA_PROPERTY" => "1", 
			"ARITHM_FUNCTION" => "1", 
			"ARROW_AUTO" => "1", 
			"ARROW_CURSOR" => "1", 
			"ARROW_FILL" => "1", 
			"ARROW_INSIDE" => "1", 
			"ARROW_OUTSIDE" => "1", 
			"ARROW_TYPE" => "1", 
			"ASSIST" => "1", 
			"AS_DISPLAYED" => "1", 
			"AUTO" => "1", 
			"AUTOMATIC" => "1", 
			"AUTO_NEW_SCREEN" => "1", 
			"AUTO_STORE_TIME" => "1", 
			"AVU_CHECK" => "1", 
			"BACKGROUND_COLOR" => "1", 
			"BALLOON" => "1", 
			"BALLOONED" => "1", 
			"BAN" => "1", 
			"BANNED" => "1", 
			"BEEP" => "1", 
			"BELOW" => "1", 
			"BEST_IMG" => "1", 
			"BETWEEN" => "1", 
			"BISECT" => "1", 
			"BLACK" => "1", 
			"BLOCK_MODE" => "1", 
			"BLUE" => "1", 
			"BORDER_COLOR" => "1", 
			"BOTH_ARROW" => "1", 
			"BOX" => "1", 
			"BOXED" => "1", 
			"BRACKETS" => "1", 
			"BREAK" => "1", 
			"BRINGTOP" => "1", 
			"BROWSE_URL" => "1", 
			"BRUSH" => "1", 
			"BSPLINE" => "1", 
			"BSPLINES" => "1", 
			"BSPL_ADD_C_PNT" => "1", 
			"BSPL_ADD_I_PNT" => "1", 
			"BSPL_DEL_C_PNT" => "1", 
			"BSPL_DEL_I_PNT" => "1", 
			"BSPL_DEL_TANGENT" => "1", 
			"BSPL_MOVE_C_PNT" => "1", 
			"BSPL_MOVE_I_PNT" => "1", 
			"BSPL_MOVE_PNT" => "1", 
			"BSPL_POINT_LENGTH" => "1", 
			"BSPL_POLYGON_FEEDBACK" => "1", 
			"BUILD_NUMBER" => "1", 
			"BUSY" => "1", 
			"BW_IMG" => "1", 
			"CANCEL" => "1", 
			"CANCEL_EDIT_DIM_TEXT" => "1", 
			"CATALOG" => "1", 
			"CATALOG_LAYOUT" => "1", 
			"CATCH" => "1", 
			"CENTER" => "1", 
			"CENTERLINE" => "1", 
			"CENTERLINES" => "1", 
			"CENTER_DASH_DASH" => "1", 
			"CENTER_LINE" => "1", 
			"CEN_BEG_END" => "1", 
			"CEN_RAD_ANG" => "1", 
			"CHAIN" => "1", 
			"CHAMFER" => "1", 
			"CHAMFER_DIMS" => "1", 
			"CHANGE_COLOR" => "1", 
			"CHANGE_CURRENT_INFO" => "1", 
			"CHANGE_DIM_ARROW" => "1", 
			"CHANGE_DIM_COLOR" => "1", 
			"CHANGE_DIM_FORMAT" => "1", 
			"CHANGE_DIM_FRAME" => "1", 
			"CHANGE_DIM_LINEWIDTH" => "1", 
			"CHANGE_DIM_OFFSET_LINE" => "1", 
			"CHANGE_DIM_OFFSET_PNT" => "1", 
			"CHANGE_DIM_PENSIZE" => "1", 
			"CHANGE_DIM_PLACES" => "1", 
			"CHANGE_DIM_TEXTS" => "1", 
			"CHANGE_DIM_TEXT_COLOR" => "1", 
			"CHANGE_DIM_TEXT_LOCATION" => "1", 
			"CHANGE_DIM_TEXT_ORIENTATION" => "1", 
			"CHANGE_DIM_VERTEX" => "1", 
			"CHANGE_ELEM_INFO" => "1", 
			"CHANGE_FILLET" => "1", 
			"CHANGE_GLOBAL_INFO" => "1", 
			"CHANGE_HATCH_ANGLE" => "1", 
			"CHANGE_HATCH_COLOR" => "1", 
			"CHANGE_HATCH_DIST" => "1", 
			"CHANGE_HATCH_LINETYPE" => "1", 
			"CHANGE_HATCH_PATTERN" => "1", 
			"CHANGE_HATCH_REF_PT" => "1", 
			"CHANGE_LEADER_ARROW" => "1", 
			"CHANGE_LEADER_ARROW_SIZE" => "1", 
			"CHANGE_LINESIZE" => "1", 
			"CHANGE_LINETYPE" => "1", 
			"CHANGE_LINEWIDTH" => "1", 
			"CHANGE_PART_REF_PT" => "1", 
			"CHANGE_PENSIZE" => "1", 
			"CHANGE_TABLE_SIZE" => "1", 
			"CHANGE_TEXT" => "1", 
			"CHANGE_TEXT_ADJUST" => "1", 
			"CHANGE_TEXT_ANGLE" => "1", 
			"CHANGE_TEXT_FILL" => "1", 
			"CHANGE_TEXT_FONTNAME" => "1", 
			"CHANGE_TEXT_FONTNAME_2BYTE" => "1", 
			"CHANGE_TEXT_FRAME" => "1", 
			"CHANGE_TEXT_LINESPACE" => "1", 
			"CHANGE_TEXT_RATIO" => "1", 
			"CHANGE_TEXT_SIZE" => "1", 
			"CHANGE_TEXT_SLANT" => "1", 
			"CHANGE_VIEWPORT_COLOR" => "1", 
			"CHANGE_VIEWPORT_SIZE" => "1", 
			"CHAR_LAYOUT" => "1", 
			"CHECK" => "1", 
			"CHECK_2D" => "1", 
			"CHECK_2D_RETAIN_DEPENDENCY" => "1", 
			"CHECK_3D_GEO_MODIFY" => "1", 
			"CHECK_BREAK" => "1", 
			"CHECK_DIM_DETAIL" => "1", 
			"CHECK_DIM_DRWSCALE" => "1", 
			"CHECK_DIM_SYMBOL" => "1", 
			"CHECK_DIM_TEXT" => "1", 
			"CHECK_ERROR" => "1", 
			"CHECK_FONT_FILLABLE" => "1", 
			"CHECK_WINDOW" => "1", 
			"CHG_CENLINE" => "1", 
			"CHG_PIXEL_COLOR" => "1", 
			"CHG_SYMLINE" => "1", 
			"CHR" => "1", 
			"CIRCLE" => "1", 
			"CIRCLES" => "1", 
			"CLEANUP_DIMS" => "1", 
			"CLEAN_CLOSE_POINTS" => "1", 
			"CLEAN_DRAWING" => "1", 
			"CLEAN_DUPLICATE_GEOMETRY" => "1", 
			"CLEAN_STACKED_GEOMETRY" => "1", 
			"CLEAR" => "1", 
			"CLEAR_KEYS" => "1", 
			"CLEAR_POSTFIX" => "1", 
			"CLEAR_PREFIX" => "1", 
			"CLEAR_SUBFIX" => "1", 
			"CLEAR_SUPERFIX" => "1", 
			"CLEAR_TOLERANCE" => "1", 
			"CLIPBOARD" => "1", 
			"CLIPBOARD_GLOBAL_SEL" => "1", 
			"CLIPBOARD_INVERSE_BW" => "1", 
			"CLIPBOARD_SELECTION" => "1", 
			"CLIPBOARD_SIZE" => "1", 
			"CLOSE" => "1", 
			"CLOSED" => "1", 
			"CLOSE_FILE" => "1", 
			"CL_ABS_OFFSET" => "1", 
			"CL_COLOR" => "1", 
			"CL_LINETYPE" => "1", 
			"CL_LINEWIDTH" => "1", 
			"CL_PENSIZE" => "1", 
			"CL_REL_OFFSET" => "1", 
			"CM" => "1", 
			"CMD_BG_COLOR" => "1", 
			"CMD_TXT_COLOR" => "1", 
			"CMP_ACCURACY" => "1", 
			"COLOR" => "1", 
			"COLOR_IMG" => "1", 
			"COLOR_LTAB" => "1", 
			"COLUMN" => "1", 
			"COLUMN_LAYOUT" => "1", 
			"COLUMN_NAME" => "1", 
			"COLUMN_NUMBER" => "1", 
			"COMMAND" => "1", 
			"CONFIGURE_EDITOR" => "1", 
			"CONFIRM" => "1", 
			"CONNECT_TABLE" => "1", 
			"CONTOUR" => "1", 
			"CONTROL" => "1", 
			"CONTROLZ_IS_EOF" => "1", 
			"CONTROL_POINTS" => "1", 
			"CONVERT" => "1", 
			"CONVERT_C_TO_B_SPLINE" => "1", 
			"CONVERT_DIM_TOLERANCE" => "1", 
			"CONVERT_DIM_UNIT" => "1", 
			"CONVERT_SPLINE" => "1", 
			"CONVERT_TO_HP_SYMBOLS" => "1", 
			"CONVERT_TO_ME10_FONT" => "1", 
			"COPY" => "1", 
			"COPY_FILE" => "1", 
			"COPY_TO_CLIPBOARD" => "1", 
			"COPY_TO_DEVICE" => "1", 
			"COS" => "1", 
			"COUNT_NEWLINE_IN_FILE" => "1", 
			"COUNT_TREE" => "1", 
			"CREATE_DETAIL" => "1", 
			"CREATE_DIRECTORY" => "1", 
			"CREATE_LTAB" => "1", 
			"CREATE_SUBPART" => "1", 
			"CREATE_VIEWPORT" => "1", 
			"CS_AXIS" => "1", 
			"CS_MIRROR" => "1", 
			"CS_REF_PT" => "1", 
			"CS_ROTATE" => "1", 
			"CS_SET" => "1", 
			"CS_SYMBOL" => "1", 
			"CURRENT" => "1", 
			"CURRENT_DIM_TEXTS" => "1", 
			"CURRENT_DIM_UNITS" => "1", 
			"CURRENT_DIRECTORY" => "1", 
			"CURRENT_FACE_HIGHLIGHT_ATTR" => "1", 
			"CURRENT_FONT" => "1", 
			"CURRENT_FONT_2BYTE" => "1", 
			"CURRENT_HATCH_PATTERN" => "1", 
			"CURRENT_HIGHLIGHT_ATTR" => "1", 
			"CURRENT_MENU" => "1", 
			"CURRENT_PART" => "1", 
			"CURRENT_SCENE" => "1", 
			"CURRENT_SCREEN" => "1", 
			"CURRENT_SPOTLIGHT_ATTR" => "1", 
			"CURRENT_TMENU" => "1", 
			"CURRENT_VERTEX_COLOR" => "1", 
			"CURRENT_VIEWPORT" => "1", 
			"CURRENT_WINDOW" => "1", 
			"CURSOR" => "1", 
			"CURSOR_COLOR" => "1", 
			"CURSOR_COORDINATES" => "1", 
			"CUT_MIDDLE" => "1", 
			"CUT_TO_CLIPBOARD" => "1", 
			"CYAN" => "1", 
			"CYCLIC" => "1", 
			"C_CIRCLE" => "1", 
			"C_CIRCLES" => "1", 
			"C_COLOR" => "1", 
			"C_GEO" => "1", 
			"C_LINE" => "1", 
			"C_LINES" => "1", 
			"C_LINETYPE" => "1", 
			"DAMP" => "1", 
			"DASHED" => "1", 
			"DASH_CENTER" => "1", 
			"DATE" => "1", 
			"DA_ARC" => "1", 
			"DA_BSPLINE" => "1", 
			"DA_CENTER_DASH_DASH" => "1", 
			"DA_CIRCLE" => "1", 
			"DA_COLOR" => "1", 
			"DA_DASHED" => "1", 
			"DA_DASH_CENTER" => "1", 
			"DA_DB_ADD" => "1", 
			"DA_DB_DELETE" => "1", 
			"DA_DB_EXPORT" => "1", 
			"DA_DB_INQ" => "1", 
			"DA_DB_LOAD" => "1", 
			"DA_DB_LOC_SCALE" => "1", 
			"DA_DB_MATCH" => "1", 
			"DA_DB_STORE" => "1", 
			"DA_DB_UNLOAD" => "1", 
			"DA_DB_WIN_CREATE" => "1", 
			"DA_DB_WIN_LOC" => "1", 
			"DA_DEFINE_DIM_SETTINGS_MACRO" => "1", 
			"DA_DIM_ANGLE" => "1", 
			"DA_DIM_ARC" => "1", 
			"DA_DIM_AUTO_LOC" => "1", 
			"DA_DIM_AUTO_STRATEGY" => "1", 
			"DA_DIM_CHAIN" => "1", 
			"DA_DIM_CHAMFER" => "1", 
			"DA_DIM_COORD" => "1", 
			"DA_DIM_DATUM_LONG" => "1", 
			"DA_DIM_DATUM_LONG_SYM" => "1", 
			"DA_DIM_DATUM_SHORT" => "1", 
			"DA_DIM_DELETE" => "1", 
			"DA_DIM_DIAMETER" => "1", 
			"DA_DIM_DTAN" => "1", 
			"DA_DIM_GEO_SENSE" => "1", 
			"DA_DIM_HOLE_INSERTION" => "1", 
			"DA_DIM_INCLINE" => "1", 
			"DA_DIM_INSERT" => "1", 
			"DA_DIM_LINE" => "1", 
			"DA_DIM_LINE_SYM" => "1", 
			"DA_DIM_PD_SCAN" => "1", 
			"DA_DIM_RADIUS" => "1", 
			"DA_DIM_SHORT_SPACE" => "1", 
			"DA_DOTTED" => "1", 
			"DA_DOT_CENTER" => "1", 
			"DA_FILLET" => "1", 
			"DA_FILTER_ACTIVATE" => "1", 
			"DA_FILTER_ACTIVE" => "1", 
			"DA_FILTER_ADD" => "1", 
			"DA_FILTER_CLEAR_GEOTYPES" => "1", 
			"DA_FILTER_CLEAR_LINETYPES" => "1", 
			"DA_FILTER_DEL_COLOR" => "1", 
			"DA_FILTER_DEL_LINESIZE" => "1", 
			"DA_FILTER_DEL_ORIENT" => "1", 
			"DA_FILTER_DEL_PENSIZE" => "1", 
			"DA_FILTER_DEL_WIDTH" => "1", 
			"DA_FILTER_INQ" => "1", 
			"DA_FILTER_NAME" => "1", 
			"DA_FILTER_REFRESH_LINESIZE" => "1", 
			"DA_FILTER_REFRESH_LINEWIDTH" => "1", 
			"DA_FILTER_REFRESH_ORIENT" => "1", 
			"DA_FILTER_REFRESH_PENSIZE" => "1", 
			"DA_FILTER_SET_NAME" => "1", 
			"DA_FILTER_STORE" => "1", 
			"DA_GEOTYPE" => "1", 
			"DA_HORIZONTAL" => "1", 
			"DA_INQ_LEVEL" => "1", 
			"DA_LINE" => "1", 
			"DA_LINESIZE" => "1", 
			"DA_LINETYPE" => "1", 
			"DA_LINEWIDTH" => "1", 
			"DA_LONG_DASHED" => "1", 
			"DA_MAKE_VALID_MACRO_NAME" => "1", 
			"DA_MOVE_DIMENSION" => "1", 
			"DA_NOT" => "1", 
			"DA_NULL" => "1", 
			"DA_NUM_ENTRIES" => "1", 
			"DA_ORIENTATION" => "1", 
			"DA_PENSIZE" => "1", 
			"DA_PHANTOM" => "1", 
			"DA_POINT" => "1", 
			"DA_SOLID" => "1", 
			"DA_SPLINE" => "1", 
			"DA_STYLE_APPLY" => "1", 
			"DA_STYLE_DEFER_UPDATE" => "1", 
			"DA_STYLE_ENABLE_UPDATE" => "1", 
			"DA_STYLE_GET" => "1", 
			"DA_STYLE_INQ" => "1", 
			"DA_STYLE_TYPE" => "1", 
			"DA_STYLE_UPDATE" => "1", 
			"DA_STYLE_WIN_CREATE" => "1", 
			"DA_STYLE_WIN_LOC" => "1", 
			"DA_STYLE_WIN_RAISE" => "1", 
			"DA_TEXT" => "1", 
			"DA_VERTICAL" => "1", 
			"DA_WRITE_DIM_SETTINGS_MACRO" => "1", 
			"DDE_ADD_TOPIC" => "1", 
			"DDE_CLOSE" => "1", 
			"DDE_ENABLE" => "1", 
			"DDE_EXECUTE" => "1", 
			"DDE_EXECUTE_SYNC" => "1", 
			"DDE_EXECUTE_TIMEOUT" => "1", 
			"DDE_INITIATE" => "1", 
			"DDE_REMOVE_TOPIC" => "1", 
			"DDE_REQUEST" => "1", 
			"DDE_REQUEST_TIMEOUT" => "1", 
			"DDE_SEND_ACK" => "1", 
			"DDE_WITHHOLD_ACK" => "1", 
			"DEFAULT" => "1", 
			"DEFER" => "1", 
			"DEFINE" => "1", 
			"DEFINE_CATALOG" => "1", 
			"DEFINE_FONT" => "1", 
			"DEFINE_KEY" => "1", 
			"DEFINE_MOUSE_KEY" => "1", 
			"DEG" => "1", 
			"DEGREE" => "1", 
			"DEG_MIN_SEC" => "1", 
			"DELETE" => "1", 
			"DELETE_CURRENT_INFO" => "1", 
			"DELETE_DIMENSION" => "1", 
			"DELETE_DIM_POSTFIX" => "1", 
			"DELETE_DIM_PREFIX" => "1", 
			"DELETE_DIM_SUBFIX" => "1", 
			"DELETE_DIM_SUPERFIX" => "1", 
			"DELETE_DIM_TOLERANCE" => "1", 
			"DELETE_ELEM_INFO" => "1", 
			"DELETE_FONT" => "1", 
			"DELETE_HATCH" => "1", 
			"DELETE_INV_RTL" => "1", 
			"DELETE_LABEL" => "1", 
			"DELETE_LTAB" => "1", 
			"DELETE_LTAB_ROW" => "1", 
			"DELETE_MACRO" => "1", 
			"DELETE_MENU" => "1", 
			"DELETE_PIXMAP" => "1", 
			"DELETE_PIXMAP_SELECTION" => "1", 
			"DELETE_TABLE" => "1", 
			"DELETE_TMENU" => "1", 
			"DELETE_VIEWPORT" => "1", 
			"DEL_OLD" => "1", 
			"DENSITY" => "1", 
			"DETAIL" => "1", 
			"DETAIL_DIM" => "1", 
			"DETAIL_INFO" => "1", 
			"DIAMETER" => "1", 
			"DIAMETER_DIMS" => "1", 
			"DIMENSIONS" => "1", 
			"DIM_2ND_DEC_PLACE" => "1", 
			"DIM_2ND_NUMBER_FORMAT" => "1", 
			"DIM_ALIGN" => "1", 
			"DIM_ALL" => "1", 
			"DIM_ANGLE" => "1", 
			"DIM_ARC" => "1", 
			"DIM_ARROW" => "1", 
			"DIM_BREAK_RESTORE" => "1", 
			"DIM_BROKEN" => "1", 
			"DIM_CATCH_LINES" => "1", 
			"DIM_CATCH_RANGE" => "1", 
			"DIM_CHAIN" => "1", 
			"DIM_CHAMFER" => "1", 
			"DIM_CHAMFER_POSTFIX" => "1", 
			"DIM_CHAMFER_PREFIX" => "1", 
			"DIM_CLEAR_VALIDS" => "1", 
			"DIM_COLOR" => "1", 
			"DIM_CONVERT_UNIT" => "1", 
			"DIM_COORD" => "1", 
			"DIM_CURSOR_POSITION" => "1", 
			"DIM_DATUM" => "1", 
			"DIM_DATUM_LONG" => "1", 
			"DIM_DATUM_LONG_SYM" => "1", 
			"DIM_DATUM_SHORT" => "1", 
			"DIM_DATUM_STEP" => "1", 
			"DIM_DEC_PLACE" => "1", 
			"DIM_DEG_MIN_SEC" => "1", 
			"DIM_DIAMETER" => "1", 
			"DIM_DIAMETER_LINE" => "1", 
			"DIM_EXTENSION_LENGTH" => "1", 
			"DIM_FONT" => "1", 
			"DIM_FORMAT" => "1", 
			"DIM_FRAME" => "1", 
			"DIM_FT_INCH_SIGN" => "1", 
			"DIM_LINE" => "1", 
			"DIM_LINES_COLOR" => "1", 
			"DIM_LINEWIDTH" => "1", 
			"DIM_LINE_SYM" => "1", 
			"DIM_MIN_SPACE" => "1", 
			"DIM_NUMBER_FORMAT" => "1", 
			"DIM_OFFSET_LINE" => "1", 
			"DIM_OFFSET_POINT" => "1", 
			"DIM_PENSIZE" => "1", 
			"DIM_POSTFIX" => "1", 
			"DIM_PREFIX" => "1", 
			"DIM_RADIUS" => "1", 
			"DIM_RADIUS_LINE" => "1", 
			"DIM_SCALE" => "1", 
			"DIM_SELECT_BY_TEXTBOX" => "1", 
			"DIM_STAGGER_RESTORE" => "1", 
			"DIM_SUBFIX" => "1", 
			"DIM_SUPERFIX" => "1", 
			"DIM_TAN" => "1", 
			"DIM_TEXT_COLOR" => "1", 
			"DIM_TEXT_FRAME_COLOR_MODE" => "1", 
			"DIM_TEXT_GAP" => "1", 
			"DIM_TEXT_HOLE" => "1", 
			"DIM_TEXT_LOCATION" => "1", 
			"DIM_TEXT_ORIENTATION" => "1", 
			"DIM_TEXT_RATIO" => "1", 
			"DIM_TEXT_SIZE" => "1", 
			"DIM_TEXT_SPACE" => "1", 
			"DIM_TOLERANCE" => "1", 
			"DIM_UNDERLINE_EDITED" => "1", 
			"DIM_UNITS" => "1", 
			"DIM_UPDATE" => "1", 
			"DIN" => "1", 
			"DIR" => "1", 
			"DIRECT" => "1", 
			"DISABLE_INQ" => "1", 
			"DISPLAY" => "1", 
			"DISPLAY_ERROR" => "1", 
			"DISPLAY_LIST" => "1", 
			"DISPLAY_NO_WAIT" => "1", 
			"DIST_ANG" => "1", 
			"DIST_DIST" => "1", 
			"DITHER" => "1", 
			"DIV" => "1", 
			"DOTTED" => "1", 
			"DOT_CENTER" => "1", 
			"DOT_GRID" => "1", 
			"DOT_TYPE" => "1", 
			"DRAWING_SCALE" => "1", 
			"DRAW_CURR_PART_ON_TOP" => "1", 
			"DRWSCALE_DIM" => "1", 
			"DUMP_SCREEN" => "1", 
			"DUMP_SCREEN_DEFAULTS" => "1", 
			"DUMP_SCREEN_IS_DIRECT" => "1", 
			"DWF" => "1", 
			"DWG" => "1", 
			"DXF" => "1", 
			"DYNAMIC" => "1", 
			"DYNAMIC_PALETTE_AUTORELOAD" => "1", 
			"ECHO" => "1", 
			"EDITED_DIMENSIONS" => "1", 
			"EDIT_CURRENT_INFO" => "1", 
			"EDIT_CURRENT_URL" => "1", 
			"EDIT_DIM_POSTFIX" => "1", 
			"EDIT_DIM_PREFIX" => "1", 
			"EDIT_DIM_SUBFIX" => "1", 
			"EDIT_DIM_SUPERFIX" => "1", 
			"EDIT_DIM_TEXT" => "1", 
			"EDIT_DIM_TOLERANCE" => "1", 
			"EDIT_ELEM_INFO" => "1", 
			"EDIT_ELEM_URL" => "1", 
			"EDIT_ENVIRONMENT" => "1", 
			"EDIT_FILE" => "1", 
			"EDIT_MACRO" => "1", 
			"EDIT_PART" => "1", 
			"EDIT_PART_URL" => "1", 
			"EDIT_PIXMAP" => "1", 
			"EDIT_PORT" => "1", 
			"EDIT_TEXT" => "1", 
			"ELEM" => "1", 
			"ELEMENT" => "1", 
			"ELSE" => "1", 
			"ELSE_IF" => "1", 
			"ENABLE_BREAK" => "1", 
			"ENABLE_INQ" => "1", 
			"END" => "1", 
			"END_DEFINE" => "1", 
			"END_IF" => "1", 
			"END_LOOP" => "1", 
			"END_PART" => "1", 
			"END_WHILE" => "1", 
			"ENHANCED" => "1", 
			"ENTER" => "1", 
			"EQUIDISTANCE" => "1", 
			"ERROR" => "1", 
			"ERROR_LOG" => "1", 
			"ERROR_STR" => "1", 
			"EXECUTE" => "1", 
			"EXECUTE_IMMEDIATE_END" => "1", 
			"EXECUTE_STRING" => "1", 
			"EXIT" => "1", 
			"EXIT_IF" => "1", 
			"EXOR" => "1", 
			"EXP" => "1", 
			"EXTEND" => "1", 
			"EXTENSION_LINE" => "1", 
			"FACES" => "1", 
			"FALSE" => "1", 
			"FBROWSER" => "1", 
			"FBROWSER_ICON" => "1", 
			"FEEDBACK_INDICATOR" => "1", 
			"FEET" => "1", 
			"FILE" => "1", 
			"FILLET" => "1", 
			"FILLETS" => "1", 
			"FILL_OFF" => "1", 
			"FILL_ON" => "1", 
			"FIRST" => "1", 
			"FIRST_ARROW" => "1", 
			"FIT" => "1", 
			"FIX" => "1", 
			"FIXED_SOURCE" => "1", 
			"FIX_UNFIX" => "1", 
			"FLAG" => "1", 
			"FLAGGED" => "1", 
			"FOLLOW" => "1", 
			"FONT" => "1", 
			"FONT_2BYTE" => "1", 
			"FORCE" => "1", 
			"FORMAT" => "1", 
			"FRACT" => "1", 
			"FRACT_INCH" => "1", 
			"FRAME_WIDTH" => "1", 
			"FRONT_STRING" => "1", 
			"FT_FRACT_INCH" => "1", 
			"FT_FR_INCH" => "1", 
			"FT_FR_IN_SIGN" => "1", 
			"FT_FR_IN_TEXT" => "1", 
			"FT_INCH_SIGN" => "1", 
			"FT_INCH_TEXT" => "1", 
			"FUNCTION" => "1", 
			"GATHER" => "1", 
			"GATHER_DIM" => "1", 
			"GENERATE" => "1", 
			"GEO" => "1", 
			"GETENV" => "1", 
			"GET_DYN_MOUSE_OLD_ZOOM_MODE" => "1", 
			"GET_ELEM_INFO" => "1", 
			"GET_PROPERTIES" => "1", 
			"GET_TYPE" => "1", 
			"GLOBAL" => "1", 
			"GRADIAN" => "1", 
			"GRAPHIC" => "1", 
			"GRD" => "1", 
			"GREEN" => "1", 
			"GRID" => "1", 
			"GRID_FACTOR" => "1", 
			"HARD" => "1", 
			"HATCH" => "1", 
			"HATCHING" => "1", 
			"HATCH_ANGLE" => "1", 
			"HATCH_COLOR" => "1", 
			"HATCH_DIST" => "1", 
			"HATCH_LINETYPE" => "1", 
			"HATCH_REF_PT" => "1", 
			"HEIGHT" => "1", 
			"HELP" => "1", 
			"HIGHLIGHT" => "1", 
			"HIGHLIGHT_LTAB" => "1", 
			"HISTORY" => "1", 
			"HL_CHANGE_COLOR" => "1", 
			"HL_CHANGE_LINETYPE" => "1", 
			"HL_CHANGE_PENSIZE" => "1", 
			"HL_DEFAULT_FACE_COLOR" => "1", 
			"HL_DELETE_FACE" => "1", 
			"HL_GENERATE_FACE" => "1", 
			"HL_GENERATE_HIDDEN" => "1", 
			"HL_GEN_ALL_PART" => "1", 
			"HL_INQ_CURR_Z_VALUE" => "1", 
			"HL_INQ_FACE_COLOR" => "1", 
			"HL_INQ_LOAD_VALUE" => "1", 
			"HL_INQ_RELATION_OFFSET" => "1", 
			"HL_INQ_Z_VALUE" => "1", 
			"HL_REDRAW_MODE" => "1", 
			"HL_SET_COLOR" => "1", 
			"HL_SET_CURR_Z_VALUE" => "1", 
			"HL_SET_FACE_COLOR" => "1", 
			"HL_SET_KEEP_COLOR" => "1", 
			"HL_SET_LINETYPE" => "1", 
			"HL_SET_LOAD_VALUE" => "1", 
			"HL_SET_PENSIZE" => "1", 
			"HL_SET_RELATION_OFFSET" => "1", 
			"HL_SET_Z_VALUE" => "1", 
			"HL_VISUALIZE" => "1", 
			"HOLES" => "1", 
			"HOR" => "1", 
			"HORIZONTAL" => "1", 
			"HPGL" => "1", 
			"HPGL2" => "1", 
			"HPGL2_RTL" => "1", 
			"HSL_COLOR" => "1", 
			"ICONIFY_WINDOW" => "1", 
			"IF" => "1", 
			"IGES" => "1", 
			"IGNORE_BREAK" => "1", 
			"ILLEGAL" => "1", 
			"IMAGE_FIT" => "1", 
			"IMMEDIATE" => "1", 
			"INCHES" => "1", 
			"INCH_OVER_MM" => "1", 
			"INCLINED" => "1", 
			"INFOS" => "1", 
			"INIT_PART" => "1", 
			"INIT_SUBPART" => "1", 
			"INPUT" => "1", 
			"INQ" => "1", 
			"INQ_ELEM" => "1", 
			"INQ_ENV" => "1", 
			"INQ_MENU" => "1", 
			"INQ_NEXT_ELEM" => "1", 
			"INQ_PART" => "1", 
			"INQ_PIX" => "1", 
			"INQ_SELECTED_ELEM" => "1", 
			"INQ_TABLE" => "1", 
			"INSERT_LTAB_ROW" => "1", 
			"INT" => "1", 
			"INTERACTIVE_INPUT" => "1", 
			"INTERSECTION" => "1", 
			"INTERSECT_WITH_BOX" => "1", 
			"INVISIBLE" => "1", 
			"ISO" => "1", 
			"ISOM" => "1", 
			"ISOMETRIC" => "1", 
			"JIS" => "1", 
			"JIS_TYPE" => "1", 
			"KEEP" => "1", 
			"KEEP_CORNER" => "1", 
			"KEEP_DATA" => "1", 
			"KEEP_DISPLAY" => "1", 
			"KEEP_ID_MAPS" => "1", 
			"KEEP_INFOS" => "1", 
			"KEEP_POINTS" => "1", 
			"KEEP_READABLE" => "1", 
			"KEEP_SCALE" => "1", 
			"KEYWORD_STAT" => "1", 
			"KM" => "1", 
			"KNOB_BOX" => "1", 
			"KNOB_BOX_FACTOR" => "1", 
			"KNOT_VECTOR" => "1", 
			"LABEL" => "1", 
			"LARGE" => "1", 
			"LAST" => "1", 
			"LAST_FEEDBACK" => "1", 
			"LAST_POSTFIX" => "1", 
			"LAST_PREFIX" => "1", 
			"LAST_PROMPT" => "1", 
			"LAST_SUBFIX" => "1", 
			"LAST_SUPERFIX" => "1", 
			"LAST_TOLERANCE" => "1", 
			"LAST_WINDOW" => "1", 
			"LAST_WINDOWS" => "1", 
			"LEADER_ARROW" => "1", 
			"LEADER_ARROW_FILL" => "1", 
			"LEADER_LINE" => "1", 
			"LEADER_LINES" => "1", 
			"LEFT" => "1", 
			"LEN" => "1", 
			"LENGTH_PAR" => "1", 
			"LET" => "1", 
			"LG" => "1", 
			"LICENSE_CHECK_TIME" => "1", 
			"LICENSE_HOLD_TIME" => "1", 
			"LICENSE_SERVER" => "1", 
			"LIMIT" => "1", 
			"LINE" => "1", 
			"LINEPATTERN" => "1", 
			"LINES" => "1", 
			"LINESIZE" => "1", 
			"LINESIZES" => "1", 
			"LINETYPE" => "1", 
			"LINEWIDTH" => "1", 
			"LINEWIDTHS" => "1", 
			"LINE_COLOR" => "1", 
			"LINE_GRID" => "1", 
			"LINE_POS" => "1", 
			"LIST_FONTS" => "1", 
			"LIST_GLOBAL_INFO" => "1", 
			"LIST_KEYWORDS" => "1", 
			"LIST_MACRO_NAMES" => "1", 
			"LIST_MENUS" => "1", 
			"LITERAL" => "1", 
			"LN" => "1", 
			"LOAD" => "1", 
			"LOAD_FONT" => "1", 
			"LOAD_HPGL" => "1", 
			"LOAD_MACRO" => "1", 
			"LOAD_METER" => "1", 
			"LOAD_MODULE" => "1", 
			"LOCAL" => "1", 
			"LONG_BASE_LINE" => "1", 
			"LONG_DASHED" => "1", 
			"LOOP" => "1", 
			"LOWER" => "1", 
			"LOWER_WINDOW" => "1", 
			"LOW_IMG" => "1", 
			"LTAB" => "1", 
			"LTAB_COLUMNS" => "1", 
			"LTAB_ROWS" => "1", 
			"LTAB_TITLES" => "1", 
			"LWC" => "1", 
			"MACRO" => "1", 
			"MACRO_EXISTS" => "1", 
			"MACRO_STAT" => "1", 
			"MAGENTA" => "1", 
			"MAIN_ALL" => "1", 
			"MAIN_DIM" => "1", 
			"MAIN_NUM" => "1", 
			"MAIN_TOL" => "1", 
			"MAKE_TMP_NAME" => "1", 
			"MAKE_WORK_DIR" => "1", 
			"MANUAL" => "1", 
			"MAP" => "1", 
			"MAP_ALL" => "1", 
			"MARK" => "1", 
			"MATCH" => "1", 
			"MATRIX" => "1", 
			"MAXIMUM" => "1", 
			"MAX_FEEDBACK" => "1", 
			"MAX_RADIUS" => "1", 
			"MEASURE_ANGLE" => "1", 
			"MEASURE_AREA" => "1", 
			"MEASURE_COORDINATE" => "1", 
			"MEASURE_DISTANCE" => "1", 
			"MEASURE_LENGTH" => "1", 
			"MEASURE_RADIUS" => "1", 
			"MEDIR" => "1", 
			"MEDIUM" => "1", 
			"MENU" => "1", 
			"MENU_BUFFER" => "1", 
			"MENU_LAYOUT" => "1", 
			"MENU_STATUS" => "1", 
			"MERGE" => "1", 
			"METERS" => "1", 
			"MEUSERDATADIR" => "1", 
			"MEXX" => "1", 
			"MI" => "1", 
			"MILES" => "1", 
			"MILS" => "1", 
			"MINIMUM" => "1", 
			"MINUS" => "1", 
			"MIN_DIST_FACTOR" => "1", 
			"MIN_LENGTH" => "1", 
			"MIN_RADIUS" => "1", 
			"MIP_DUMMY" => "1", 
			"MIP_FIND_MAX_POSNR" => "1", 
			"MIP_INPUT_CHECK" => "1", 
			"MIP_IS_MACRO_VARIABLE_SET" => "1", 
			"MIP_SHAFT" => "1", 
			"MIRR" => "1", 
			"MIRROR" => "1", 
			"MIX" => "1", 
			"MM" => "1", 
			"MM_OVER_INCH" => "1", 
			"MOD" => "1", 
			"MODIFY" => "1", 
			"MODIFY_DIM_LINES" => "1", 
			"MOVE" => "1", 
			"MOVE_DIMENSION" => "1", 
			"MOVE_TABLE" => "1", 
			"MSWINDOW_EMF_CLIPBOARD" => "1", 
			"MSWINDOW_GDI_PRINTER" => "1", 
			"MT" => "1", 
			"MULTIPLE" => "1", 
			"M_REDO" => "1", 
			"M_UNDO" => "1", 
			"NATURAL" => "1", 
			"NEIGHBORS" => "1", 
			"NEW" => "1", 
			"NEW_SCREEN" => "1", 
			"NEXT" => "1", 
			"NO" => "1", 
			"NOBAN" => "1", 
			"NONE" => "1", 
			"NORM_VIDEO" => "1", 
			"NOSUBPART" => "1", 
			"NOT" => "1", 
			"NO_ARC_DIMS" => "1", 
			"NO_BACKUP" => "1", 
			"NO_CATCH" => "1", 
			"NO_CENTER_LINE" => "1", 
			"NO_CHAMFER_DIMS" => "1", 
			"NO_CHECK" => "1", 
			"NO_DELAY" => "1", 
			"NO_ERROR" => "1", 
			"NO_EXTENSION_LINE" => "1", 
			"NO_KEEP" => "1", 
			"NO_LINETYPE_ADJUST" => "1", 
			"NO_RAISE" => "1", 
			"NO_SIGN" => "1", 
			"NO_STANDARD" => "1", 
			"NO_TOL" => "1", 
			"NO_TOLERANCE" => "1", 
			"NO_VIEWPORT_RANGE" => "1", 
			"NULL" => "1", 
			"NUM" => "1", 
			"NUMBER" => "1", 
			"OF" => "1", 
			"OFF" => "1", 
			"OFFSET" => "1", 
			"ON" => "1", 
			"ONLY" => "1", 
			"ON_ERROR" => "1", 
			"OPEN" => "1", 
			"OPEN_INFILE" => "1", 
			"OPEN_OUTFILE" => "1", 
			"OPPOSITE" => "1", 
			"OR" => "1", 
			"ORDER" => "1", 
			"ORIGIN" => "1", 
			"OTHER" => "1", 
			"OUTPUT_HP15" => "1", 
			"OUTPUT_HP16" => "1", 
			"OUTPUT_STRING" => "1", 
			"OVERDRAW" => "1", 
			"PAN" => "1", 
			"PAN_SEL" => "1", 
			"PARALLEL" => "1", 
			"PARALLEL_TO_LINE" => "1", 
			"PARAMETER" => "1", 
			"PARENT" => "1", 
			"PART" => "1", 
			"PARTS" => "1", 
			"PARTS_LIST" => "1", 
			"PARTS_LIST_FORMAT" => "1", 
			"PART_BOX" => "1", 
			"PART_DRW_SCALE" => "1", 
			"PART_DRW_SCALE_REF" => "1", 
			"PART_ICON" => "1", 
			"PART_NUMBER_OFFSET" => "1", 
			"PART_ORIGIN" => "1", 
			"PASTE_FROM_CLIPBOARD" => "1", 
			"PATTERN" => "1", 
			"PB_HIGHLIGHT" => "1", 
			"PB_LTAB_UPDATE" => "1", 
			"PB_SCROLL" => "1", 
			"PCL" => "1", 
			"PD_ANGLE_LINES" => "1", 
			"PD_AUTO_ANGLE_TOLERANCE" => "1", 
			"PD_AUTO_SAME_DISTANCE_TOLERANCE" => "1", 
			"PD_AUTO_SYMMETRY_COLOR" => "1", 
			"PD_AUTO_SYMMETRY_LINE" => "1", 
			"PD_AUTO_SYMMETRY_LINETYPE" => "1", 
			"PD_AUTO_TANGENT_TOLERANCE" => "1", 
			"PD_AUTO_ZERO_DISTANCE_TOLERANCE" => "1", 
			"PD_CLEAN_DRAWING" => "1", 
			"PD_COLLINEAR" => "1", 
			"PD_DEFAULT_DIM_COLOR" => "1", 
			"PD_DEFAULT_DIM_TEXT_SIZE" => "1", 
			"PD_DIMENSION" => "1", 
			"PD_DISTANCE" => "1", 
			"PD_ELEM" => "1", 
			"PD_FILLET" => "1", 
			"PD_FIX" => "1", 
			"PD_FREE" => "1", 
			"PD_HIDE_DIMENSIONS" => "1", 
			"PD_HORIZONTAL" => "1", 
			"PD_INFO_CONSTRAINT" => "1", 
			"PD_INFO_ELEMENT" => "1", 
			"PD_MAKE_DIMENSIONS" => "1", 
			"PD_MIRROR" => "1", 
			"PD_MODIFY_DIMENSION" => "1", 
			"PD_NEW_C_LINE_COLOR" => "1", 
			"PD_NEW_C_LINE_LINETYPE" => "1", 
			"PD_NEW_C_LINE_VISIBILITY" => "1", 
			"PD_NEW_POINT_COLOR" => "1", 
			"PD_NEW_POINT_LINETYPE" => "1", 
			"PD_NEW_POINT_VISIBILITY" => "1", 
			"PD_PARALLEL" => "1", 
			"PD_PARAM_ADD" => "1", 
			"PD_PARAM_FIX" => "1", 
			"PD_PARAM_INQ" => "1", 
			"PD_PARAM_REMOVE" => "1", 
			"PD_PARAM_SAVE" => "1", 
			"PD_PARAM_SHOW" => "1", 
			"PD_PERPENDICULAR" => "1", 
			"PD_POINT" => "1", 
			"PD_POINT_ON" => "1", 
			"PD_PREVIEW_COLOR" => "1", 
			"PD_RESOLVE" => "1", 
			"PD_RESOLVE_MERGE_TOLERANCE" => "1", 
			"PD_RIGID_ADD" => "1", 
			"PD_RIGID_REMOVE" => "1", 
			"PD_RIGID_SHOW" => "1", 
			"PD_RIGID_TABLE_REFRESH" => "1", 
			"PD_SAME_DISTANCE" => "1", 
			"PD_SAME_SIZE" => "1", 
			"PD_SHOW" => "1", 
			"PD_SHOW_CLEAR" => "1", 
			"PD_SHOW_COLOR" => "1", 
			"PD_SHOW_DISABLE" => "1", 
			"PD_SHOW_ENABLE" => "1", 
			"PD_SHOW_LABEL_SIZE" => "1", 
			"PD_SHOW_MOVE_TEXT" => "1", 
			"PD_SHOW_USE_POSTFIX" => "1", 
			"PD_SIZE" => "1", 
			"PD_SLOPE" => "1", 
			"PD_SYM_LINE" => "1", 
			"PD_TANGENT" => "1", 
			"PD_USE_DIMENSION" => "1", 
			"PD_VERTICAL" => "1", 
			"PD_ZONE_ADD" => "1", 
			"PD_ZONE_REMOVE" => "1", 
			"PD_ZONE_SHOW" => "1", 
			"PENSIZE" => "1", 
			"PENSIZES" => "1", 
			"PENWIDTH" => "1", 
			"PERF_MON_OFF" => "1", 
			"PERF_MON_ON" => "1", 
			"PERIODIC" => "1", 
			"PERMANENT" => "1", 
			"PERMANENT_TRANS" => "1", 
			"PERPENDICULAR" => "1", 
			"PERPEND_TO_LINE" => "1", 
			"PER_RAD_ANG" => "1", 
			"PHANTOM" => "1", 
			"PI" => "1", 
			"PICK_VP_PNT" => "1", 
			"PIXMAP_EDITOR" => "1", 
			"PIXMAP_LIST" => "1", 
			"PIXMAP_SCROLL" => "1", 
			"PLAIN" => "1", 
			"PLOT" => "1", 
			"PLOTTER_TYPE" => "1", 
			"PLOT_AUTO_ROTATE" => "1", 
			"PLOT_CENTER" => "1", 
			"PLOT_DESTINATION" => "1", 
			"PLOT_FORMAT" => "1", 
			"PLOT_IMAGE_QUALITY" => "1", 
			"PLOT_LINETYPE_LENGTH" => "1", 
			"PLOT_PEN_TABLE" => "1", 
			"PLOT_SCALE" => "1", 
			"PLOT_STOP_ON_ERROR" => "1", 
			"PLOT_TRANSFORMATION" => "1", 
			"PLOT_VIEWPORT" => "1", 
			"PLUS" => "1", 
			"PLUS_MINUS" => "1", 
			"PNT" => "1", 
			"PNT3" => "1", 
			"PNT_MM" => "1", 
			"PNT_PIXEL" => "1", 
			"PNT_RA" => "1", 
			"PNT_XY" => "1", 
			"PNT_XYS" => "1", 
			"PNT_XYZ" => "1", 
			"POINT" => "1", 
			"POINTER" => "1", 
			"POINTS" => "1", 
			"POINT_PAR" => "1", 
			"POLY" => "1", 
			"POLYELEM" => "1", 
			"POLYELEMENTS" => "1", 
			"POLYGON" => "1", 
			"POP_DOWN_LTAB" => "1", 
			"POP_UP_LTAB" => "1", 
			"PORT" => "1", 
			"POS" => "1", 
			"POSITION" => "1", 
			"POSTFIX" => "1", 
			"POSTSCRIPT" => "1", 
			"PREFIX" => "1", 
			"PREVIEW" => "1", 
			"PREVIOUS" => "1", 
			"PRE_VIEW" => "1", 
			"PRE_VIEW_WIN_MAP" => "1", 
			"PRE_VIEW_WIN_MOVE" => "1", 
			"PRINTER" => "1", 
			"PRINT_FB" => "1", 
			"PRINT_TABLE" => "1", 
			"PROJ_ANGLE" => "1", 
			"PROMPT" => "1", 
			"PROMPT_LINE" => "1", 
			"PROMPT_LIST" => "1", 
			"PRT_EDITOR" => "1", 
			"PSEUDO_COMMAND" => "1", 
			"PT_ANG" => "1", 
			"PT_ANG_DIST" => "1", 
			"PURGE_FILE" => "1", 
			"PUTENV" => "1", 
			"PUT_PROPERTIES" => "1", 
			"QUALIFIER" => "1", 
			"RAD" => "1", 
			"RADIAN" => "1", 
			"RADIUS_DIMS" => "1", 
			"RAISE_WINDOW" => "1", 
			"RANGE" => "1", 
			"RATIO" => "1", 
			"RC_ACCURACY" => "1", 
			"RC_CHECK" => "1", 
			"RC_CMP_DIMLINES" => "1", 
			"READ" => "1", 
			"READ_FILE" => "1", 
			"READ_LTAB" => "1", 
			"READ_ONLY" => "1", 
			"RECALL_BUFFER" => "1", 
			"RECALL_WINDOW" => "1", 
			"RECALL_WINDOWS" => "1", 
			"RECTANGLE" => "1", 
			"RECURSIVE" => "1", 
			"RED" => "1", 
			"REDRAW" => "1", 
			"REFLINE" => "1", 
			"REFLINES" => "1", 
			"REF_PNT" => "1", 
			"REF_PT" => "1", 
			"REGENERATE" => "1", 
			"RELATIVE" => "1", 
			"RENAME" => "1", 
			"RENAME_PART" => "1", 
			"RENOVATE" => "1", 
			"REPAIR" => "1", 
			"REPEAT" => "1", 
			"REPLACE" => "1", 
			"REQUEST_PRINT_SETUP" => "1", 
			"REREAD" => "1", 
			"RESET" => "1", 
			"RESET_PART_NUMBER" => "1", 
			"RETAIN_RASTER" => "1", 
			"REVERSE" => "1", 
			"REVERSE_SORT" => "1", 
			"REVERSE_VIDEO" => "1", 
			"RGB_COLOR" => "1", 
			"RIGHT" => "1", 
			"RND" => "1", 
			"ROT" => "1", 
			"ROTATE" => "1", 
			"ROTATE_DIM_TEXT" => "1", 
			"ROUND" => "1", 
			"ROW" => "1", 
			"ROWS" => "1", 
			"RPT" => "1", 
			"RTL_COLOR" => "1", 
			"RTL_DST_GAP" => "1", 
			"RTL_LINETYPE" => "1", 
			"RTL_LINEWIDTH" => "1", 
			"RTL_OFFSET" => "1", 
			"RTL_OLD_BEHAVIOUR" => "1", 
			"RTL_PENSIZE" => "1", 
			"RTL_SRC_GAP" => "1", 
			"RUBBER_ARC_BEG_END" => "1", 
			"RUBBER_ARC_CEN_BEG" => "1", 
			"RUBBER_ARC_CEN_END" => "1", 
			"RUBBER_BOX" => "1", 
			"RUBBER_CIRCLE_2_PTS" => "1", 
			"RUBBER_CIRCLE_CEN" => "1", 
			"RUBBER_LINE" => "1", 
			"RUBBER_LINE_ANG" => "1", 
			"RUBBER_LINE_HORIZONTAL" => "1", 
			"RUBBER_LINE_VERTICAL" => "1", 
			"RULER" => "1", 
			"RUN" => "1", 
			"RUN_OPTION" => "1", 
			"SAME" => "1", 
			"SAVE" => "1", 
			"SAVE_ENVIRONMENT" => "1", 
			"SAVE_FONT" => "1", 
			"SAVE_LTAB" => "1", 
			"SAVE_MACRO" => "1", 
			"SAVE_MENU" => "1", 
			"SAVE_TABLE" => "1", 
			"SAVE_TMENU" => "1", 
			"SAVE_VIEWPORT" => "1", 
			"SCALE" => "1", 
			"SCENE" => "1", 
			"SCREEN" => "1", 
			"SCREEN_MAPPING" => "1", 
			"SCREEN_TRANSFORMATION" => "1", 
			"SCROLL_BAR" => "1", 
			"SCROLL_LTAB" => "1", 
			"SD" => "1", 
			"SEARCH" => "1", 
			"SECURE_LTAB" => "1", 
			"SECURE_MACRO" => "1", 
			"SECURE_TABLE" => "1", 
			"SEC_ALL" => "1", 
			"SEC_ARROW" => "1", 
			"SEC_DIM" => "1", 
			"SEC_NUM" => "1", 
			"SEC_TOL" => "1", 
			"SELECT" => "1", 
			"SELECT_DIM_ARROW" => "1", 
			"SELECT_FROM_LTAB" => "1", 
			"SELECT_KNOB" => "1", 
			"SELECT_PORT" => "1", 
			"SENDBACK" => "1", 
			"SERIAL" => "1", 
			"SET_COLOR" => "1", 
			"SET_DIR" => "1", 
			"SET_DYN_MOUSE_OLD_ZOOM_MODE" => "1", 
			"SET_MASK" => "1", 
			"SET_PIXMAP_TRANSPARENCY" => "1", 
			"SGN" => "1", 
			"SHARED_PART" => "1", 
			"SHARE_ACCURACY_LOAD" => "1", 
			"SHARE_PART" => "1", 
			"SHIFT" => "1", 
			"SHIFT_LEFT" => "1", 
			"SHIFT_RIGHT" => "1", 
			"SHORT_BASE_LINE" => "1", 
			"SHOW" => "1", 
			"SHOW_CPOLY" => "1", 
			"SHOW_INV_RTL" => "1", 
			"SHOW_PART" => "1", 
			"SHOW_PIX_BOX" => "1", 
			"SHOW_PIX_OFF" => "1", 
			"SHOW_PIX_ON" => "1", 
			"SHOW_POPUP_MENU" => "1", 
			"SHOW_TABLE" => "1", 
			"SHOW_TABLE_PAGE" => "1", 
			"SILENT" => "1", 
			"SIMILAR" => "1", 
			"SIN" => "1", 
			"SLANT" => "1", 
			"SLASH_TYPE" => "1", 
			"SL_COLOR" => "1", 
			"SL_LINETYPE" => "1", 
			"SL_LINEWIDTH" => "1", 
			"SL_OFFSET" => "1", 
			"SL_PENSIZE" => "1", 
			"SMALL" => "1", 
			"SMASH_POLY" => "1", 
			"SMASH_SUBPART" => "1", 
			"SMOOTH" => "1", 
			"SNID" => "1", 
			"SOFT" => "1", 
			"SOLID" => "1", 
			"SORT" => "1", 
			"SORT_LTAB" => "1", 
			"SPLINE" => "1", 
			"SPLINES" => "1", 
			"SPLINE_CONVERSION" => "1", 
			"SPLIT" => "1", 
			"SPLITTING" => "1", 
			"SPOTLIGHT" => "1", 
			"SQR" => "1", 
			"SQRT" => "1", 
			"STAGGERED" => "1", 
			"STANDARD" => "1", 
			"STATLINE_RESET" => "1", 
			"STATUS" => "1", 
			"STORE" => "1", 
			"STORE_202" => "1", 
			"STORE_210" => "1", 
			"STORE_211" => "1", 
			"STORE_240" => "1", 
			"STORE_250" => "1", 
			"STORE_FONT" => "1", 
			"STORE_IN_RECALL_BUFFER" => "1", 
			"STORE_KEYS" => "1", 
			"STORE_MACRO" => "1", 
			"STORE_WINDOW" => "1", 
			"STORE_WINDOWS" => "1", 
			"STR" => "1", 
			"STRETCH" => "1", 
			"STRING" => "1", 
			"SUBFIX" => "1", 
			"SUBPART" => "1", 
			"SUBSTR" => "1", 
			"SUBTRACT" => "1", 
			"SUBTREE" => "1", 
			"SUPERFIX" => "1", 
			"SYMBOL" => "1", 
			"SYMBOL_DIM" => "1", 
			"SYMBOL_PART" => "1", 
			"SYMLINE" => "1", 
			"SYMLINES" => "1", 
			"SYSTEM" => "1", 
			"S_OF" => "1", 
			"TABLE" => "1", 
			"TABLET_RESET" => "1", 
			"TABLE_COLUMN" => "1", 
			"TABLE_LAYOUT" => "1", 
			"TABLE_SCROLL_STEP" => "1", 
			"TABLE_STATUS" => "1", 
			"TABLE_TITLE" => "1", 
			"TAN" => "1", 
			"TAN2" => "1", 
			"TAN2_PT" => "1", 
			"TAN3" => "1", 
			"TANGENT" => "1", 
			"TANGENTIAL" => "1", 
			"TAN_CENTER" => "1", 
			"TAN_PT" => "1", 
			"TAN_PT_PT" => "1", 
			"TECHO" => "1", 
			"TERMINATOR_TYPE" => "1", 
			"TEXT" => "1", 
			"TEXTS" => "1", 
			"TEXT_ADJUST" => "1", 
			"TEXT_ANGLE" => "1", 
			"TEXT_COLOR" => "1", 
			"TEXT_DIM" => "1", 
			"TEXT_FEEDBACK" => "1", 
			"TEXT_FILL" => "1", 
			"TEXT_FRAME" => "1", 
			"TEXT_HOLE_INSERTION" => "1", 
			"TEXT_LINESPACE" => "1", 
			"TEXT_ONLY" => "1", 
			"TEXT_POS" => "1", 
			"TEXT_RATIO" => "1", 
			"TEXT_SCALE" => "1", 
			"TEXT_SIZE" => "1", 
			"TEXT_SLANT" => "1", 
			"TEXT_TO_GEO" => "1", 
			"TF_BOX" => "1", 
			"TF_TEXT" => "1", 
			"THREE_PTS" => "1", 
			"TIME" => "1", 
			"TINPUT" => "1", 
			"TITLE" => "1", 
			"TITLE_LAYOUT" => "1", 
			"TMENU" => "1", 
			"TOGGLE_DIR" => "1", 
			"TOGGLE_SELECT" => "1", 
			"TOGGLE_SORT" => "1", 
			"TONE" => "1", 
			"TOP" => "1", 
			"TO_CLIPBOARD" => "1", 
			"TRACE" => "1", 
			"TRACKING" => "1", 
			"TRAP_ERROR" => "1", 
			"TREE" => "1", 
			"TRIANGLE_TYPE" => "1", 
			"TRIM" => "1", 
			"TRIMMING" => "1", 
			"TRIM_ONE" => "1", 
			"TRIM_TWO" => "1", 
			"TRUE" => "1", 
			"TRUE_COLOR_PLOTTING" => "1", 
			"TRUNC" => "1", 
			"TR_ASSIGN" => "1", 
			"TR_CHANGE_CASE_CONV" => "1", 
			"TR_CHANGE_COLUMN" => "1", 
			"TR_CHANGE_LINES" => "1", 
			"TR_CHANGE_PRECISION" => "1", 
			"TR_CHANGE_WIDTH" => "1", 
			"TR_CHANGE_WORD_WRAP" => "1", 
			"TR_EXTRACT_VALUE" => "1", 
			"TR_SET_CASE_CONV" => "1", 
			"TR_SET_COLUMN" => "1", 
			"TR_SET_LINES" => "1", 
			"TR_SET_PRECISION" => "1", 
			"TR_SET_WIDTH" => "1", 
			"TR_SET_WORD_WRAP" => "1", 
			"TR_SHOW" => "1", 
			"TR_UNASSIGN" => "1", 
			"TR_UPDATE" => "1", 
			"TWO_PTS" => "1", 
			"TXT_WINDOW" => "1", 
			"TYPE" => "1", 
			"UA_ANGLE_GRID" => "1", 
			"UA_CENTER_CATCH_RANGE" => "1", 
			"UA_COPILOT" => "1", 
			"UA_DESIGN_INTENT" => "1", 
			"UA_DIMENSION_FEEDBACK" => "1", 
			"UA_DISTANCE_GRID" => "1", 
			"UA_GET_CENTER_CATCH_RANGE" => "1", 
			"UA_GET_COPILOT" => "1", 
			"UA_GET_DESIGN_INTENT" => "1", 
			"UA_GET_PERPENDICULAR_CATCH_RANGE" => "1", 
			"UA_GET_SNAP_ANGLE" => "1", 
			"UA_GET_SNAP_DIST" => "1", 
			"UA_GET_TANGENT_CATCH_RANGE" => "1", 
			"UA_PERPENDICULAR_CATCH_RANGE" => "1", 
			"UA_SET_CATCH_DELAY" => "1", 
			"UA_TANGENT_CATCH_RANGE" => "1", 
			"UINCHES" => "1", 
			"UM" => "1", 
			"UNDERLINE_SOURCE" => "1", 
			"UNDO" => "1", 
			"UNFIX" => "1", 
			"UNITS" => "1", 
			"UNLOAD_MODULE" => "1", 
			"UNMAP" => "1", 
			"UNMAP_ALL" => "1", 
			"UNREGISTERED" => "1", 
			"UNSECURE_TABLE" => "1", 
			"UNSHARE_ACCURACY" => "1", 
			"UNSHARE_BACK" => "1", 
			"UNSHARE_PART" => "1", 
			"UNTIL" => "1", 
			"UNUSED" => "1", 
			"UPC" => "1", 
			"UPDATE_SCREEN" => "1", 
			"UPPER" => "1", 
			"UPPER_LOWER" => "1", 
			"USED" => "1", 
			"USED_MULTIPLE" => "1", 
			"USER" => "1", 
			"USER_CRD" => "1", 
			"USER_PAR" => "1", 
			"USE_MULTILINE_HATCH" => "1", 
			"USE_NEW_FILE_FEATURES" => "1", 
			"VAL" => "1", 
			"VER" => "1", 
			"VERSION" => "1", 
			"VERTEX" => "1", 
			"VERTEX_3D" => "1", 
			"VERTICAL" => "1", 
			"VIEW" => "1", 
			"VIEWPORT_CATCH" => "1", 
			"VIOLATED" => "1", 
			"VISIBLE" => "1", 
			"VRML" => "1", 
			"WAIT" => "1", 
			"WARNING" => "1", 
			"WHILE" => "1", 
			"WHITE" => "1", 
			"WHO_PROGRAMMED" => "1", 
			"WIDTH" => "1", 
			"WINDOW" => "1", 
			"WINEXEC" => "1", 
			"WINPLOT" => "1", 
			"WRITE_FILE" => "1", 
			"WRITE_LTAB" => "1", 
			"X_OF" => "1", 
			"YARDS" => "1", 
			"YELLOW" => "1", 
			"YES" => "1", 
			"Y_OF" => "1", 
			"ZOOM" => "1", 
			"Z_OF" => "1", 
			"+" => "4", 
			"-" => "4", 
			"//" => "4", 
			"/" => "4", 
			"%" => "4", 
			"&" => "4", 
			">" => "4", 
			"<" => "4", 
			"^" => "4", 
			"!" => "4", 
			"|" => "4");

// Special extensions

// Each category can specify a PHP function that returns an altered
// version of the keyword.
        
        

$this->linkscripts    	= array(
			"" => "donothing", 
			"4" => "donothing", 
			"1" => "donothing");
}


function donothing($keywordin)
{
	return $keywordin;
}

}?>
