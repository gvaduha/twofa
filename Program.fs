open System
open System.IO

open platform
open mocks
open websrv

let reply (response:StreamWriter) body =
    response.Write("HTTP/1.1 200 OK\r\n\r\n<HTML><HEAD><title>TwoFA proto</title></head><BODY>" + body + "</BODY></HTML>")

(* *** page renderers with mad HTML/JS skills *** *)
let loginPage = fun _ ->
    "<H1>Login</H1>user: <input type='text' id='user'><br>pass: <input type='password'><br><a href=\"javascript:window.location.href='/2fa/'+document.getElementById('user').value\">LOGIN</a>"

let secretPage (vars: string list) =
    sprintf
        "<H1>Pair your device</H1>secret is<br>%s<br>QR<br>code: <input type='text' id='code'><br><a href=\"javascript:window.location.href='/2fa/'+window.location.href.split('/').pop()+'/'+document.getElementById('code').value\">PROCEED</a>"
        vars.Head

let codeConfirmPage = fun _ ->
    "<H1>Confirmation code</H1>code: <input type='text' id='code'><br><a href=\"javascript:window.location.href='/check2fa/'+window.location.href.split('/').pop()+'/'+document.getElementById('code').value\">CONFIRM</a>"

let codefailPage = fun _ ->
    "<a href=\"javascript:window.location.href=window.location.href.substr(0,window.location.href.lastIndexOf('/')\"><H1 style='color:red'>FAILED</H1></a>"

let loginsuccPage = fun (vars: string list) ->
    "<H1>"+" Welcome on board</H1><br><a href='/'>back</a>"

let acclockPage = fun _ ->
    "<H1>Account is LOCKED</H1><a href='/reset'>reset</a><br><a href='/'>back to site root</a>"

let resetPage = fun _ ->
    "<H1>Reset 2FA</H1>user: <input type='text' id='user'><br><a href='/reset/'+document.getElementById('user').value\">RESET</a>"
(* END page renderers with mad HTML/JS skills END *)


let srvrouter (ctrl:SecondFactorAuthController) (boctrl:BackofficeAccountController) (header:string, response:StreamWriter) =
   let resource = header.Split(' ').[1].Split('/')
   match resource.[1] with
   | "login" -> reply response (loginPage [])
   | "2fa" -> 
            let page = ctrl.RunState resource.[2] ""
            reply response page
   | "check2fa" ->
            let page = ctrl.RunState resource.[2] resource.[3]
            reply response page
   | "reset" ->
            let vars = match (resource.Length > 2) with
                        | true -> [resource.[2]]
                        | false -> []
            reply response (boctrl.RunState vars)
   | _ -> reply response "<a href='/login'>Login</a><br><a href='/reset'>Unlock account</a>" 


[<EntryPoint>]
let main _ =
    let factor = new TotpAuthenticationFactor(new TotpAuthenticationFactorConfig())
    let accstore = new UserAccountStore("@svr.")
    let renderers = new SecondFactorAuthControllerStates(secretPage, codeConfirmPage, codefailPage, loginsuccPage, acclockPage)
    let ctrl = new SecondFactorAuthController(new SecondFactorAuthControllerConfig(), accstore, factor, renderers)
    let borend = new BackofficeAccountControllerStates(resetPage, loginPage)
    let boctrl = new BackofficeAccountController(accstore, borend)
    printfn "serving@localhost:8080..."
    startServer("127.0.0.1", 8080) (srvrouter ctrl boctrl)
    Console.ReadLine() |> ignore
    0

