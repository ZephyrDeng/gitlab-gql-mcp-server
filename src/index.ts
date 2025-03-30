import { GitlabMCPServer } from "./server";
import { GitlabRestfulApiTool } from "./tools/GitlabRestfulApiTool"
// 使用自定义服务器
const server = new GitlabMCPServer({
    tools: [
        new GitlabRestfulApiTool()
    ]
});

// 启动服务器
server.start();

// 处理关闭信号
process.on("SIGINT", async () => {
  await server.stop();
});