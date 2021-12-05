using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;

namespace MultiblockSHA256
{
    class Program
    {
        static int Main(params string[] args)
        {
            var cmd = new RootCommand("Calculate SHA256 multi block signature of file.") { TreatUnmatchedTokensAsErrors = true };
            cmd.AddOption(new Option(new[] { "--path", "-p" }, "The path to the file.", typeof(string)) { IsRequired = true });
            cmd.AddOption(new Option(new[] { "--blockSize", "-s" }, "The target size of blocks in bytes.", typeof(long), () => 1024L * 1024L * 1024L));
            cmd.Handler = CommandHandler.Create<string, long>(Main);

            var result = cmd.Invoke(args);

            return result;


            //var path = @"D:\backup\dummy.dat";

            //using (var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None))
            //{
            //    fs.SetLength(30 * 1024L * 1024L * 1024L);
            //}

            //return 0;
        }

        static int Main(string path, long blockSize)
        {
            var watch = Stopwatch.StartNew();
            var fileInfo = new FileInfo(path);

            if (!fileInfo.Exists)
            {
                Console.WriteLine("File not found.");
                return -1;
            }

            var fileLength = fileInfo.Length;

            Console.WriteLine($"File length is ~ {(double)fileLength / 1024 / 1024:F1} MB");

            var fullBlocksCount = fileLength / blockSize;
            var finalBlockSize = fileLength % blockSize;
            var queue = new ConcurrentQueue<BlockInfo>();
            var allBlocks = new List<BlockInfo>();

            checked
            {
                for (var i = 0; i < fullBlocksCount; i++)
                {
                    allBlocks.Add(new BlockInfo(i, i * blockSize, blockSize));
                }

                if (finalBlockSize > 0)
                {
                    allBlocks.Add(new BlockInfo((int)fullBlocksCount, fullBlocksCount * blockSize, finalBlockSize));
                }
            }

            Console.WriteLine($"Blocks found {allBlocks.Count}");

            foreach (var item in allBlocks)
            {
                queue.Enqueue(item);
            }

            // Note https://github.com/dotnet/runtime/issues/29686
            var parallelism = new[] { Environment.ProcessorCount, allBlocks.Count }.Min();

            var allThreads = new List<Thread>(parallelism);

            for (var i = 0; i < parallelism; i++)
            {
                var thread = new Thread(t => ThreadProcess(path, queue)) { Name = $"#{i}", IsBackground = true };
                allThreads.Add(thread);
                thread.Start();
            }

            for (var i = 0; i < parallelism; i++)
            {
                // should we add timeout here?
                allThreads[i].Join();
            }

            watch.Stop();

            // output hashes in same order as blocks
            foreach (var blockInfo in allBlocks.OrderBy(x => x.Sequence))
            {
                for (var i = 0; i < blockInfo.Sha256.Length; i++)
                {
                    Console.Write($"{blockInfo.Sha256[i]:X2}");
                }

                Console.WriteLine();
            }

            Console.WriteLine();
            Console.WriteLine(watch.ElapsedMilliseconds);

            return 0;
        }

        private static void ThreadProcess(string fileName, ConcurrentQueue<BlockInfo> blocksQueue)
        {
            using (var fs = new FileStream(fileName, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                while (blocksQueue.TryDequeue(out var block))
                {
                    using (var sha = new SHA256Managed())
                    {
                        var bufferSize = new[] { block.Size, 16L * 1024L * 1024L }.Min(); // should check for memory opacity, threads count?
                        var buffer = new byte[bufferSize];

                        fs.Position = block.Offset;

                        var steps = block.Size / bufferSize;
                        var finalReadCount = block.Size % bufferSize;

                        if (finalReadCount == 0)
                        {
                            finalReadCount = bufferSize;
                        }
                        else
                        {
                            steps += 1;
                        }

                        for (var i = 0; i < steps; i++)
                        {
                            var isFinalStep = i == steps - 1;
                            var expectedCount = (int)(isFinalStep ? finalReadCount : bufferSize);
                            var count = fs.Read(buffer, 0, expectedCount);

                            if (count != expectedCount)
                            {
                                throw new Exception($"Expected length {expectedCount} got {count}.");
                            }

                            if (isFinalStep)
                            {
                                sha.TransformFinalBlock(buffer, 0, expectedCount);
                            }
                            else
                            {
                                sha.TransformBlock(buffer, 0, expectedCount, buffer, 0);
                            }
                        }

                        block.Sha256 = new byte[sha.Hash.Length];
                        Array.Copy(sha.Hash, block.Sha256, sha.Hash.Length);
                    }

                    Console.WriteLine($"Block #{block.Sequence} processed on thread {Thread.CurrentThread.Name}.");
                }
            }
        }

        private class BlockInfo
        {
            public BlockInfo(int sequence, long offset, long size)
            {
                this.Sequence = sequence;
                this.Offset = offset;
                this.Size = size;
            }

            public int Sequence { get; set; }

            public long Offset { get; set; }

            public long Size { get; set; }

            public byte[] Sha256 { get; set; }
        }
    }
}
