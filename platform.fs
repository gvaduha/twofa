module platform

open System
open System.Security.Cryptography
// https://github.com/wiry-net/Wiry.Base32
open Wiry.Base32
// https://github.com/kspearrin/Otp.NET
open OtpNet

type StrongAuthFactorStatus = NotConfigured = 'N' | Enabled = 'E' | Disabled = 'D'

type StrongAuthFactorAccountSettings(status:StrongAuthFactorStatus, secret:string, faultAttempts:uint8) =
    let sharedsecret = secret
    member __.Status = status
    member __.FaultAttempts = faultAttempts
    member __.Secret
        with get() =
            //assert (status <> StrongAuthFactorStatus.Enabled) // Shared secret shouldn't be used if auth is not enabled
            sharedsecret
    
type AuthAccountSettings(secondfactor:StrongAuthFactorAccountSettings, locked:bool) =
    member __.SecondFactor = secondfactor
    member __.Locked = locked

type IAuthenticationFactorAccountStorage =
    abstract member GetStrongAuthFactorAccountSettings: string -> AuthAccountSettings
    abstract member SetStrongAuthFactorAccountSettings: string -> AuthAccountSettings -> unit

type IBackendAuthenticationFactorAccountControl =
    // Enable account and set second factor to NotConfigured state
    abstract member ResetAccountSecondFactor: string -> unit
    
/// TOTP algorithm settings
type TotpAuthenticationFactorConfig() =
    // truncate auth code to this value
    member __.Size = 6
    // auth code valid time frame in seconds
    member __.Step = 30
    // auth code frame of tolerance window (-n <- code -> +n)
    member __.Window = 2;

/// TOTP algorithm
type TotpAuthenticationFactor(config:TotpAuthenticationFactorConfig) =
    let rng = new RNGCryptoServiceProvider()
    let config = config
    let mutable disposed = false;

    let cleanup(disposing:bool) = 
        if not disposed then
            disposed <- true
            if disposing then
                rng.Dispose ()
            ()

    interface IDisposable with
        member __.Dispose() =
            cleanup(true)
            GC.SuppressFinalize(__)

    override __.Finalize() = 
        cleanup(false)

    // generates 32 bytes of shared secret
    member __.GenerateSharedSecret =
        let random = "12345678901234567890"B // 20 is needed to generate 32 bytes
        rng.GetBytes random; // could trigger exceptions
        let ret = Base32Encoding.Standard.GetString random
        ret

    // generate TOTP
    member __.GenerateTOTP (secret:string) =
        let secraw = System.Text.Encoding.ASCII.GetBytes secret
        let totp = new Totp(secraw, config.Step, OtpHashMode.Sha1, config.Size, TimeCorrection.UncorrectedInstance)
        totp.ComputeTotp

    // verify TOTP
    member __.VerifyTOTP (secret:string) code =
        let secraw = System.Text.Encoding.ASCII.GetBytes secret
        let totp = new Totp(secraw, config.Step, OtpHashMode.Sha1, config.Size, TimeCorrection.UncorrectedInstance)
        let window = new VerificationWindow(config.Window, config.Window)
        let mutable time:int64 = int64 0
        let res = totp.VerifyTotp(code, &time, window)
        res

type PageRenderer = string list -> string

type SecondFactorAuthControllerStates(secretPage:PageRenderer, CodeConfirmPage:PageRenderer,
                                      codefailPage:PageRenderer, loginsuccPage:PageRenderer, 
                                      acclockPag:PageRenderer) =
    member __.SecretPage = secretPage
    member __.CodeConfirmPage = CodeConfirmPage
    member __.CodeFailPage = codefailPage
    member __.LoginSuccPage = loginsuccPage
    member __.AccLockPage = acclockPag


type SecondFactorAuthControllerConfig() =
    member __.MaxFaultAttempts:uint8 = uint8 3

(*
@startuml
title SecondFactorAuthController State Model
[*] --> LoginPassed : correct user and password
LoginPassed --> AccountLocked
LoginPassed --> ShareSecret : not configured
ShareSecret --> CodeConfirmation
LoginPassed --> CodeConfirmation : 2FA enabled
LoginPassed --> LoginSucceeded : 2FA disabled
CodeConfirmation --> LoginSucceeded : correct code
CodeConfirmation --> CodeFailure
CodeFailure --> CodeConfirmation
CodeFailure --> AccountLocked : fault threshold
LoginSucceeded -> [*]
AccountLocked -> [*]
ShareSecret: generate 32 byte base32 secret
CodeConfirmation: confirm range of codes n<-time->n
LoginSucceeded: proceed with requested page
CodeFailure: increment and store faults
@enduml*)
type SecondFactorAuthController(config:SecondFactorAuthControllerConfig, store:IAuthenticationFactorAccountStorage,
                                secfact:TotpAuthenticationFactor, renderers:SecondFactorAuthControllerStates) =
    let config = config
    let store = store
    let secfact = secfact
    let r = renderers

    let resetFaultAttempts login (auth:AuthAccountSettings) =
        let newauth = new AuthAccountSettings(
                            new StrongAuthFactorAccountSettings(
                                    auth.SecondFactor.Status,
                                    auth.SecondFactor.Secret,
                                    uint8 0),
                            auth.Locked)
        store.SetStrongAuthFactorAccountSettings login auth

    let incrementFaultAttempts login (auth:AuthAccountSettings) =
        let newauth = new AuthAccountSettings(
                            new StrongAuthFactorAccountSettings(
                                    auth.SecondFactor.Status,
                                    auth.SecondFactor.Secret,
                                    uint8 0),
                            auth.Locked)
        store.SetStrongAuthFactorAccountSettings login auth

    let lockAccount login (auth:AuthAccountSettings) =
        let newauth = new AuthAccountSettings(
                            new StrongAuthFactorAccountSettings(
                                    auth.SecondFactor.Status,
                                    auth.SecondFactor.Secret,
                                    auth.SecondFactor.FaultAttempts),
                            true)
        store.SetStrongAuthFactorAccountSettings login auth

    member __.RunState login code =
        let auth = store.GetStrongAuthFactorAccountSettings login
        match auth.Locked with
        | true -> r.AccLockPage []
        | false ->
            match auth.SecondFactor.Status with
                | StrongAuthFactorStatus.NotConfigured -> 
                    let newauth = new StrongAuthFactorAccountSettings(StrongAuthFactorStatus.Enabled, secfact.GenerateSharedSecret, uint8 0)
                    store.SetStrongAuthFactorAccountSettings login (new AuthAccountSettings(newauth, true))
                    r.CodeConfirmPage [newauth.Secret]
                | StrongAuthFactorStatus.Enabled ->
                    match code with
                    | "" -> r.CodeConfirmPage []
                    | c -> match secfact.VerifyTOTP auth.SecondFactor.Secret c with
                           | true ->
                                resetFaultAttempts login auth
                                r.LoginSuccPage []
                           | false -> match auth.SecondFactor.FaultAttempts < config.MaxFaultAttempts with
                                      | true ->
                                                incrementFaultAttempts login auth
                                                r.CodeFailPage []
                                      | false ->
                                                lockAccount login auth
                                                r.AccLockPage []
                | StrongAuthFactorStatus.Disabled ->
                    resetFaultAttempts login auth
                    r.LoginSuccPage []
                | _ -> "" // raise alarm here



type BackofficeAccountControllerStates(resetPage:PageRenderer, afterResetPage:PageRenderer) =
    member __.ResetPage = resetPage
    member __.AfterResetPage = afterResetPage

type BackofficeAccountController(store:IAuthenticationFactorAccountStorage, r:BackofficeAccountControllerStates) =
    let store = store
    let r=r

    let resetAccount login =
        let newauth = new AuthAccountSettings(
                            new StrongAuthFactorAccountSettings(
                                    StrongAuthFactorStatus.NotConfigured,
                                    "",
                                    uint8 0),
                            true)
        store.SetStrongAuthFactorAccountSettings login newauth

    member __.RunState (vars: string list) =
        match vars.Length > 0 with
        | false -> r.ResetPage []
        | true ->
            resetAccount vars.Head
            r.AfterResetPage []