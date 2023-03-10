import "pe"

rule match3{
    meta:
        author = "Joe Khawand"
        description = "Matches the Rich header of 5ffecf27b187bcaec80b45b570631e5bd53672b23dedb4d28d4e3dc6e81214b1 and other similar samples"
    strings:
  	 	$key={9E DB EF AA}
  	 	$raw_data={DA BA 81 F9 9E DB EF AA 9E DB EF AA 9E DB EF AA
  	 	23 94 79 AA 9F DB EF AA 80 89 7A AA 8F DB EF AA
  	 	80 89 6C AA E7 DB EF AA B9 1D 94 AA 99 DB EF AA
  	 	9E DB EE AA 4E DB EF AA 80 89 6B AA DF DB EF AA
  	 	80 89 7B AA 9F DB EF AA 80 89 7E AA 9F DB EF AA
  	 	52 69 63 68}

    condition:
        $key and $raw_data  and pe.rich_signature.offset==128
}