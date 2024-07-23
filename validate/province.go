package validate

func rangeInt(start, end int) []int {
	r := make([]int, end-start+1)
	for i := range r {
		r[i] = start + i
	}
	return r
}

type ZipCodeRange struct {
	From int
	To   int
}

type ProvinceData struct {
	Name         string
	BPSCode      string
	VehiclePlate []string
	Tel          []int
	ZipCode      []ZipCodeRange
}

func concat(a, b []int) []int {
	return append(a, b...)
}

var PROVINCE_DATA = map[string]ProvinceData{
	"11": {
		Name:         "Aceh",
		BPSCode:      "11",
		VehiclePlate: []string{"BL", "LH"},
		Tel:          append(rangeInt(641, 659), 627, 629),
		ZipCode: []ZipCodeRange{
			{From: 23111, To: 24794},
		},
	},
	"32": {
		Name:         "Jawa Barat",
		BPSCode:      "32",
		VehiclePlate: []string{"D", "E", "F", "T", "Z"},
		Tel:          append(rangeInt(231, 234), concat(rangeInt(260, 267), []int{22, 251})...),
		ZipCode: []ZipCodeRange{
			{From: 16110, To: 17730},
			{From: 40111, To: 46476},
		},
	},
	"33": {
		Name:         "Jawa Tengah",
		BPSCode:      "33",
		VehiclePlate: []string{"G", "H", "K", "R", "AA", "AD"},
		Tel:          append(rangeInt(271, 289), concat(rangeInt(271, 273), []int{24, 356})...),
		ZipCode: []ZipCodeRange{
			{From: 50111, To: 54474},
			{From: 56111, To: 59584},
		},
	},
}
