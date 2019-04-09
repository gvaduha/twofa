module mocks

open System.IO

open platform

type UserAccountStore(fileprefix) =
    let fileprefix = fileprefix

    let getStoredState login =
        let name = fileprefix+login
        let str = 
            try
                File.ReadAllText (name)
            with
            | _ -> "0 N XXX 99"
        let data = str.Split(' ')
        new AuthAccountSettings(
            new StrongAuthFactorAccountSettings(
                (LanguagePrimitives.EnumOfValue data.[1].[0]),
                data.[2], 
                uint8 data.[3]),
            data.[0] = "1"
        )
    
    let setStoredState login (auth:AuthAccountSettings) =
        let str = (match auth.Locked with true -> "1" | _ -> "0") + " "
                  + string (LanguagePrimitives.EnumToValue auth.SecondFactor.Status) + " "
                  + auth.SecondFactor.Secret + " "
                  + string auth.SecondFactor.FaultAttempts
        let name = fileprefix+login
        File.WriteAllText (name, str)

    interface IAuthenticationFactorAccountStorage with
        member __.GetStrongAuthFactorAccountSettings login =
            getStoredState login
        member __.SetStrongAuthFactorAccountSettings login auth =
            setStoredState login auth

    interface IBackendAuthenticationFactorAccountControl with
        member __.ResetAccountSecondFactor login =
            setStoredState login (new AuthAccountSettings(
                                        new StrongAuthFactorAccountSettings(
                                            StrongAuthFactorStatus.NotConfigured,
                                            "",
                                            uint8 99),
                                        false))
