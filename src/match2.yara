import "pe"
import "math"
rule match2{
    meta:
        author = "Joe Khawand"
        description = "Rule to match samples similar to : 5ffecf27b187bcaec80b45b570631e5bd53672b23dedb4d28d4e3dc6e81214b1"
    strings:
        $rich_key={9E DB EF AA}
    condition:
        (not pe.is_dll() and pe.number_of_signatures == 0) and
        for any i in (0..pe.number_of_sections-1):
        (
            math.entropy(pe.sections[i].raw_data_offset,pe.sections[i].raw_data_size) > 7.5
        )
        and for any i in (0..pe.number_of_sections-1):
        (
            pe.sections[i].virtual_size<10
        )
        and $rich_key
        and pe.checksum == pe.calculate_checksum()
        and pe.rich_signature.offset==128
}