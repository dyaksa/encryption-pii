package npwp

const NPWP_REGEX = `^(\d{2})(\d{3})(\d{3})(\d{1})(\d{3})(\d{3})$`

const NPWP_LENGTH = 15

var NPWP_TAX_IDENTITIES = []string{
	"01", "02", "21", "31", "00", "20", "04", "05", "06", "07", "08", "09", "24", "25", "26",
	"31", "34", "35", "36", "41", "47", "42", "48", "49", "57", "58", "64", "65", "67", "71", "77", "78", "79", "87", "88",
	"89", "91", "97",
}

var NPWP_DOT_INDEXES = []int{1, 4, 7, 11}

var NPWP_HYPHEN_INDEXES = []int{8}
