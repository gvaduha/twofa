module websrv

open System
open System.IO
open System.Net
open System.Net.Sockets

let acceptClient (client:TcpClient) handler = async {
   use stream = client.GetStream()
   use reader = new StreamReader(stream)
   let header = reader.ReadLine()
   if not (String.IsNullOrEmpty(header)) then
      use writer = new StreamWriter(stream)
      handler (header, writer)
      writer.Flush()
   }

let startServer (address: string, port) handler =
   let ip = IPAddress.Parse(address)
   let listener = TcpListener(ip, port)
   listener.Start() 
   async { 
      while true do 
         let! client = listener.AcceptTcpClientAsync() |> Async.AwaitTask
         acceptClient client handler |> Async.Start
   }
   |> Async.Start

type StreamWriter with
   member writer.BinaryWrite(bytes:byte[]) =
      let writer = new BinaryWriter(writer.BaseStream)
      writer.Write(bytes)
