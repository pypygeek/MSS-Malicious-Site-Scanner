rule html_test
{
    strings: $a = "html"
    condition: $a
}