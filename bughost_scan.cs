
using RuriLib.Parallelization;
using RuriLib.Parallelization.Models;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Runtime.InteropServices;
using System.Net.NetworkInformation;
using System.Net;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography.X509Certificates;

namespace ParallelizationDemo
{


    internal class bughost_scan

    {

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetConsoleTitle(string lpConsoleTitle);

        private static async Task Main(string[] args)

        {

            string asciiArt = @"
╔══╗             ╔╗ ╔╗        ╔════╗    ╔═══╗             
║╔╗║             ║║ ║║        ║╔╗╔╗║    ║╔═╗║             
║╚╝╚╗╔╗╔╗╔══╗    ║╚═╝║╔══╗╔══╗╚╝║║╚╝    ║╚══╗╔══╗╔══╗ ╔═╗ 
║╔═╗║║║║║║╔╗║    ║╔═╗║║╔╗║║══╣  ║║      ╚══╗║║╔═╝╚ ╗║ ║╔╗╗
║╚═╝║║╚╝║║╚╝║    ║║ ║║║╚╝║╠══║ ╔╝╚╗     ║╚═╝║║╚═╗║╚╝╚╗║║║║
╚═══╝╚══╝╚═╗║    ╚╝ ╚╝╚══╝╚══╝ ╚══╝     ╚═══╝╚══╝╚═══╝╚╝╚╝
         ╔═╝║      __| |_______________________________| |__                                          
         ╚══╝     (__| |_______________________________| |__)
                     | |  ( OI | VIVO | TIM | CLARO )  | |   
                   __| |_______________________________| |__ 
                  (__|_|_______________________________|_|__)


";

            ConsoleColor[] colors = { ConsoleColor.Red, ConsoleColor.Yellow, ConsoleColor.Green, ConsoleColor.Blue, ConsoleColor.Magenta };

            int colorIndex = 0;

            for (int i = 0; i < asciiArt.Length; i++)
            {
                Console.ForegroundColor = colors[colorIndex];

                Console.Write(asciiArt[i]);

                colorIndex++;

                if (colorIndex >= colors.Length)
                {
                    colorIndex = 0;
                }
            }

            Console.ResetColor();

            Console.WriteLine("Selecione a operadora desejada:");
            Console.WriteLine("1. OPERADORA1");
            Console.WriteLine("2. OPERADORA2");
            Console.WriteLine("3. OPERADORA3");
            Console.WriteLine("4. OPERADORA4");
            Console.WriteLine("5. OUTRA OPERADORA");
            Console.Write("Informe o número da operadora: ");
            int operadoraSelecionada = int.Parse(Console.ReadLine());
            string nomeOperadora;

            switch (operadoraSelecionada)
            {
                case 1:
                    nomeOperadora = "OI";
                    break;

                case 2:
                    nomeOperadora = "VIVO";
                    break;

                case 3:
                    nomeOperadora = "TIM";
                    break;

                case 4:
                    nomeOperadora = "CLARO";
                    break;

                case 5:
                    Console.Write("Digite o número da operadora: ");
                    nomeOperadora = Console.ReadLine();
                    break;

                default:
                    Console.WriteLine("Operadora inválida");
                    return;
            }

            Console.ResetColor();
            Console.Clear();
            Console.Write(asciiArt);

            Random random4 = new Random();
            ConsoleColor foregroundColor4;
            do
            {
                foregroundColor4 = (ConsoleColor)random4.Next(1, 16);
            } while (foregroundColor4 == ConsoleColor.Black);
            Console.ForegroundColor = foregroundColor4;
            Console.WriteLine("Selecione o arquivo de texto que contém a lista de domínios:");
            string[] files = Directory.GetFiles("DOMINIOS", "*.txt");
            for (int i = 0; i < files.Length; i++)
            {
                Console.WriteLine($"{i + 1}. {Path.GetFileName(files[i])}");
            }
            int selectedFileIndex;
            while (true)
            {
                Console.Write("Digite o número do arquivo que deseja selecionar: ");
                string input = Console.ReadLine();
                if (int.TryParse(input, out selectedFileIndex) && selectedFileIndex >= 1 && selectedFileIndex <= files.Length)
                {
                    selectedFileIndex--;
                    break;
                }
                Console.WriteLine("Por favor, digite um número válido.");
            }
            string[] domains = File.ReadAllLines(files[selectedFileIndex]);
            string selectedFilePath = files[selectedFileIndex];


            Console.Clear();
            Console.Write(asciiArt);
            Console.ResetColor();

            Random random16 = new Random();
            ConsoleColor foregroundColor16;
            do
            {
                foregroundColor16 = (ConsoleColor)random16.Next(1, 16);
            } while (foregroundColor16 == ConsoleColor.Black);
            var interfaces = NetworkInterface.GetAllNetworkInterfaces();

            Console.WriteLine("Selecione a interface " + nomeOperadora);
            for (int i = 0; i < interfaces.Length; i++)
            {
                Console.WriteLine($"{i + 1}. {interfaces[i].Name}");
            }

            var selectedInterfaceIndex = int.Parse(Console.ReadLine()) - 1;
            var selectedInterface = interfaces[selectedInterfaceIndex];


            Console.ResetColor();
            Console.Clear();
            Console.Write(asciiArt);
            Random random17 = new Random();
            ConsoleColor foregroundColor17;
            do
            {
                foregroundColor17 = (ConsoleColor)random17.Next(1, 16);
            } while (foregroundColor17 == ConsoleColor.Black);
            Console.ForegroundColor = foregroundColor4;

            Console.WriteLine("Escolha o nível de verbose (1, 2 ou 3):");
            string verboseLevel = Console.ReadLine();

            while (verboseLevel != "1" && verboseLevel != "2" && verboseLevel != "3")
            {
                Console.WriteLine("Opção inválida! Escolha o nível de verbose (1, 2 ou 3):");
                verboseLevel = Console.ReadLine();
            }


            string folderName = "CONFIGURACÕES";
            string fileName = "Scan.json";

            if (!Directory.Exists(folderName))
            {
                Directory.CreateDirectory(folderName);
            }

            string settingsPath = Path.Combine(folderName, fileName);

            if (File.Exists(settingsPath))
            {
                string json = File.ReadAllText(settingsPath);
                JObject settings = JObject.Parse(json);

                int porta = (int)settings["porta"];

                int portaproxy = (int)settings["portaproxy"];

                int timeouttcp = (int)settings["timeouttcp"];

                int timeoutpayload = (int)settings["timeoutpayload"];

                int thread = (int)settings["thread"];

                List<string> meuhost = settings["meuhost"].ToObject<List<string>>();

                string ProxyReverso = (string)settings["ProxyReverso"];

                bool ProxyReversoAtivado = (bool)settings["ProxyReversoAtivado"];

                string[] payloads = File.ReadAllLines("PAYLOADS/payloads.txt");

                bool sslAtivado = (bool)settings["enableSsl"];

                bool ProxyDNS = (bool)settings["ProxyDNS"];



                _ = MainAsync(meuhost, porta, sslAtivado, domains, payloads, nomeOperadora, selectedInterface, verboseLevel, thread, selectedFilePath, timeoutpayload, timeouttcp, ProxyDNS, portaproxy, ProxyReverso, ProxyReversoAtivado);
                Console.ReadLine();
            }
            else
            {
                Console.WriteLine("Arquivo de configuração 'Configurações scan.json' não encontrado.");
            }

        }

        private static async Task MainAsync(List<string> meuhost, int porta, bool sslAtivado, string[] domains, string[] payloads, string nomeOperadora, NetworkInterface selectedInterface, string verboseLevel, int thread, string selectedFilePath, int timeouttcp, int timeoutpayload, bool ProxyDNS, int portaproxy, string ProxyReverso, bool ProxyReversoAtivado)
        {
            int domainsCount = domains.Length;
            int lastProcessedIndex = 0;
            string progressFilePath = $"RETOMAR SCAN/{Path.GetFileNameWithoutExtension(selectedFilePath)}.progress";
            if (File.Exists(progressFilePath))
            {
                lastProcessedIndex = int.Parse(File.ReadAllText(progressFilePath));
            }

            var responseCodeCounters = new Dictionary<string, int>
                            {
                                { "1xx", 0 },
                                { "2xx", 0 },
                                { "3xx", 0 },
                                { "4xx", 0 },
                                { "5xx", 0 }
                            };

            var ipAddress = selectedInterface.GetIPProperties().UnicastAddresses
            .Where(addr => addr.Address.AddressFamily == AddressFamily.InterNetwork)
            .Select(addr => addr.Address)
            .FirstOrDefault();

            if (ipAddress == null)
            {
                Console.WriteLine($"Erro: interface {selectedInterface.Name} não tem um endereço IPv4 configurado.");
            }

            Func<string, CancellationToken, Task<bool>> tcpConnect = new(async (domain, token) =>
            {

                try

                {
                    var endpoint = new IPEndPoint(ipAddress, 0);
                    var client = new TcpClient();
                    client.Client.Bind(endpoint);
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
                    cts.CancelAfter(TimeSpan.FromSeconds(timeouttcp));
                    await client.ConnectAsync(domain, porta, cancellationToken: cts.Token);

                    string serverAddress = null;
                    if (ProxyDNS)
                    {
                        serverAddress = Dns.GetHostAddresses(domain)[0].ToString();
                    }
                    else
                    {
                        serverAddress = domain;
                    }
                    using var streampay = client.GetStream();
                    SslStream sslStream = null;

                    if (sslAtivado)
                    {
                        sslStream = new SslStream(streampay, false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
                        await sslStream.AuthenticateAsClientAsync(domain);
                    }

                    int progress = (int)Math.Round((double)lastProcessedIndex / (double)domainsCount * 100);
                    string progressBar = $"[{new string('|', progress / 2)}{new string('-', 50 - progress / 2)}]";
                    File.WriteAllText(progressFilePath, lastProcessedIndex.ToString());
                    lastProcessedIndex++;


                    string connectionEstablished = "HTTP/1.1 200 Connection established\r\n\r\n";
                    bool firstConnection = true;





                    foreach (string currentHost in meuhost)
                    {
                        Console.Write($"HOST JSON SENDO TESTADO: " + currentHost + "\r\n");

                        foreach (string splitPayload in payloads)
                        {

                                string[] payloadParts = splitPayload.Split(new[] { "[split]" }, StringSplitOptions.RemoveEmptyEntries);

                                for (int i = 0; i < payloadParts.Length; i++)
                                {
                                    string formattedPayload = payloadParts[i]
                                        .Replace("meuhost", currentHost)
                                        .Replace("bughost", domain)
                                        .Replace("[crlf]", $"\r\n", StringComparison.OrdinalIgnoreCase);



                                    string meuhostBughostReplaced = splitPayload
                                   .Replace("meuhost", currentHost)
                                   .Replace("bughost", domain);

                                    string allReplacesInOneLine = string.Concat(meuhostBughostReplaced.Split(Environment.NewLine.ToCharArray(), StringSplitOptions.RemoveEmptyEntries));

                                    using (TcpClient clientpayalod = new TcpClient(new IPEndPoint(ipAddress, 0)))
                                    {
                                        if (ProxyReversoAtivado)
                                        {
                                            await clientpayalod.ConnectAsync(ProxyReverso, portaproxy);
                                            using var cts2 = CancellationTokenSource.CreateLinkedTokenSource(token);
                                            cts2.CancelAfter(TimeSpan.FromSeconds(timeouttcp)); 

                                        }
                                        else
                                        {
                                            await clientpayalod.ConnectAsync(serverAddress, porta);
                                            using var cts2 = CancellationTokenSource.CreateLinkedTokenSource(token); 
                                            cts2.CancelAfter(TimeSpan.FromSeconds(timeouttcp));
                                        }

                                        if (clientpayalod.Connected)

                                        {
                                            byte[] dataToSend = Encoding.ASCII.GetBytes(formattedPayload);
                                            using NetworkStream stream = clientpayalod.GetStream();
                                            using var cts2 = CancellationTokenSource.CreateLinkedTokenSource(token); 
                                            cts2.CancelAfter(TimeSpan.FromSeconds(timeoutpayload));
                                            await stream.WriteAsync(dataToSend, cts2.Token);


                                            byte[] responseBuffer = new byte[50];
                                            int bytesRead = 0;
                                            string response = string.Empty;
                                            var responseTask = clientpayalod.GetStream().ReadAsync(responseBuffer, 0, responseBuffer.Length, token);
                                            if (await Task.WhenAny(responseTask, Task.Delay(TimeSpan.FromSeconds(2), token)) == responseTask)
                                            {
                                                bytesRead = await responseTask;
                                                response = Encoding.ASCII.GetString(responseBuffer, 0, bytesRead);
                                            }
                                            else
                                            {
                                                throw new TimeoutException("Timeout atingido durante a leitura da resposta." + "\r\n");
                                            }



                                            string[] responseLines = response.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
                                            string responseCode = responseLines.FirstOrDefault(line => line.StartsWith("HTTP"))?.Split(' ')[1] ?? "vazio";
                                            string serverType = responseLines.FirstOrDefault(line => line.StartsWith("Server:"))?.Substring("Server:".Length)?.Trim() ?? "vazio";

                                            if (!string.IsNullOrEmpty(responseCode) && int.TryParse(responseCode.Substring(0, 1), out int firstDigit))
                                            {
                                                string counterKey = $"{firstDigit}xx";
                                                if (responseCodeCounters.ContainsKey(counterKey))
                                                {
                                                    responseCodeCounters[counterKey]++;
                                                }
                                            }

                                            string titleBarText = $"HuuDeus Scan Bug Host ( OI | VIVO | TIM | CLARO ) *** RESULTADOS RESPONSE CODE - | ";

                                            foreach (var kvp in responseCodeCounters)
                                            {
                                                titleBarText += $"{kvp.Key} \"{kvp.Value}\" | ";
                                            }
                                            titleBarText = titleBarText.TrimEnd('|');

                                            Console.Title = titleBarText + $"PROCESSO \r{progressBar} {progress}% ";

                                            if (verboseLevel == "1")
                                            {
                                                Console.ForegroundColor = ConsoleColor.Green;
                                                Console.WriteLine(domain + ":" + porta);
                                                Console.ResetColor();
                                                Console.ForegroundColor = ConsoleColor.DarkCyan;
                                                Console.Write($"{domain}:{porta} | {responseCode} | {serverType}" + "\r\n");
                                                Console.ResetColor();
                                                Console.WriteLine($"Endereço IP do servidor {(ProxyDNS ? "DNS" : "remoto")}: {serverAddress}");
                                                Console.WriteLine($"Proxy Remoto {(ProxyReversoAtivado ? "Ativado" : "Desativado")}: {ProxyReverso}" + ":" + portaproxy + "\r\n");



                                            }
                                            else if (verboseLevel == "2")
                                            {
                                                Console.ForegroundColor = ConsoleColor.Green;
                                                Console.WriteLine(domain + ":" + porta);
                                                Console.ResetColor();

                                                Console.ForegroundColor = ConsoleColor.DarkYellow;
                                                Console.Write($"INJETANDO PAYLOAD: " + "\r\n");
                                                Console.ResetColor();

                                                Console.ForegroundColor = ConsoleColor.DarkYellow;
                                                Console.WriteLine(allReplacesInOneLine + "\r\n");
                                                Console.ResetColor();

                                                Console.ForegroundColor = ConsoleColor.DarkCyan;
                                                Console.Write($"{domain}:{porta} | {responseCode} | {serverType}" + "\r\n");
                                                Console.ResetColor();
                                                Console.WriteLine($"Endereço IP do servidor {(ProxyDNS ? "DNS" : "remoto")}: {serverAddress}");
                                                Console.WriteLine($"Proxy Remoto {(ProxyReversoAtivado ? "Ativado" : "Desativado")}: {ProxyReverso}" + ":" + portaproxy + "\r\n");



                                            }
                                            else if (verboseLevel == "3")
                                            {
                                                Console.ForegroundColor = ConsoleColor.Green;
                                                Console.WriteLine(domain + ":" + porta);
                                                Console.ResetColor();

                                                Console.ForegroundColor = ConsoleColor.DarkYellow;
                                                Console.Write($"INJETANDO PAYLOAD: " + "\r\n");
                                                Console.ResetColor();

                                                Console.ForegroundColor = ConsoleColor.DarkYellow;
                                                Console.WriteLine(allReplacesInOneLine + "\r\n");
                                                Console.ResetColor();

                                                Console.ForegroundColor = ConsoleColor.DarkCyan;
                                                Console.Write($"{domain}:{porta} | {responseCode} | {serverType}" + "\r\n");
                                                Console.ResetColor();


                                                Console.WriteLine(response);
                                                Console.WriteLine($"Endereço IP do servidor {(ProxyDNS ? "DNS" : "remoto")}: {serverAddress}");
                                                Console.WriteLine($"Proxy Remoto {(ProxyReversoAtivado ? "Ativado" : "Desativado")}: {ProxyReverso}" + ":" + portaproxy + "\r\n");



                                            }

                                            string projectDirectory = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
                                            string resultsDirectory = Path.Combine(projectDirectory, "RESULTADOS DO SCAN");
                                            string subdirectoryOperadora = Path.Combine(resultsDirectory, nomeOperadora + "_" + DateTime.Now.ToString("dd-MM-yyyy"));
                                            string responseText = "\r\n" + "================== HuuDeus BuG HosT ==================" + "\r\n\r\n" + $"{domain}:{porta} | {responseCode} | {serverType}" + "\r\n" + allReplacesInOneLine + "\r\n" + ($"Proxy Remoto {(ProxyReversoAtivado ? "Ativado" : "Desativado")}: {ProxyReverso}" + ":" + portaproxy + "\r\n") + ($"Endereço IP do servidor {(ProxyDNS ? "DNS" : "remoto")}: {serverAddress}" + "\r\n");
                                            string resultFileName = "RESULTADO_" + nomeOperadora + ".txt";

                                            if (!Directory.Exists(subdirectoryOperadora))
                                            {
                                                Directory.CreateDirectory(subdirectoryOperadora);
                                            }

                                            string codigoResposta = responseCode.Substring(0, 1) + "XX";
                                            string subdirectoryCodigo = Path.Combine(subdirectoryOperadora, codigoResposta);
                                            if (!Directory.Exists(subdirectoryCodigo))
                                            {
                                                Directory.CreateDirectory(subdirectoryCodigo);
                                            }

                                            string filePath = Path.Combine(subdirectoryCodigo, resultFileName);
                                            File.AppendAllText(filePath, responseText);

                                            string apenasHostResultados = Path.Combine(subdirectoryOperadora, "APENAS HOST RESULTADO");
                                            if (!Directory.Exists(apenasHostResultados))
                                            {
                                                Directory.CreateDirectory(apenasHostResultados);
                                            }

                                            string apenasHostTexto = $"{domain}";

                                            string apenasHostArquivoNome = $"{codigoResposta}.txt";

                                            string apenasHostArquivo = Path.Combine(apenasHostResultados, apenasHostArquivoNome);
                                            File.AppendAllText(apenasHostArquivo, apenasHostTexto + Environment.NewLine);

                                        }

                                    }

                                }
                        }

                    }

                    return false;
                }


                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"{domain}: {ex.Message}" + "\r\n");
                    Console.ResetColor();
                    return false;
                }


            });

            var parallelizer = ParallelizerFactory<string, bool>.Create(
                type: ParallelizerType.TaskBased,
                workItems: domains,
                workFunction: tcpConnect,
                degreeOfParallelism: thread,
                totalAmount: domains.Length,
                skip: 0);

            parallelizer.Completed += (sender, e) => OnCompleted(sender, e, selectedFilePath);
            parallelizer.Error += OnException;
            parallelizer.TaskError += OnTaskError;

            await parallelizer.Start();
            var cts = new CancellationTokenSource();
            cts.CancelAfter(5000);
            await parallelizer.WaitCompletion(cts.Token);


        }

        private static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }

        private static void OnCompleted(object sender, EventArgs e, string selectedFilePath)
        {
            Console.WriteLine("Todas as conexões foram testadas!");
            string progressFilePath = $"RETOMAR SCAN/{Path.GetFileNameWithoutExtension(selectedFilePath)}.progress";

            File.Delete(progressFilePath);
        }




        private static void OnTaskError(object sender, ErrorDetails<string> details)
            => Console.WriteLine($"Erro ao processar o domínio {details.Item}: {details.Exception.Message}");

        private static void OnException(object sender, Exception ex) => Console.WriteLine($"Exception: {ex.Message}");

    }

}