import burp.*;
import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.StringJoiner;

public class SQLInjectionTester implements IBurpExtender, IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("BURP-SQLMAP");
        callbacks.registerContextMenuFactory(this);
        callbacks.printOutput("BURP-SQLMAP loaded successfully.");
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menu = new ArrayList<>();
        JMenuItem item = new JMenuItem("Copy as sqlmap command");

        item.addActionListener(e -> generateSqlmapCommand(invocation));
        menu.add(item);
        return menu;
    }

    private void generateSqlmapCommand(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] selectedItems = invocation.getSelectedMessages();
        if (selectedItems == null || selectedItems.length == 0) {
            JOptionPane.showMessageDialog(null, "No HTTP request selected.");
            return;
        }

        for (IHttpRequestResponse item : selectedItems) {
            IRequestInfo info = helpers.analyzeRequest(item);
            URL url = info.getUrl();
            List<String> headers = info.getHeaders();
            byte[] request = item.getRequest();

            String command = buildSqlmapCommand(url, headers, request, info);
            copyToClipboard(command);
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(null, "sqlmap command copied to clipboard:\n" + command);
            });
        }
    }

    private void copyToClipboard(String text) {
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        StringSelection stringSelection = new StringSelection(text);
        clipboard.setContents(stringSelection, null);
        callbacks.printOutput("sqlmap command copied to clipboard.");
    }

    private String buildSqlmapCommand(URL url, List<String> headers, byte[] request, IRequestInfo info) {
        StringBuilder command = new StringBuilder("sqlmap -u \"" + url + "\"");

        // Adding headers, skipping the request line
        for (int i = 1; i < headers.size(); i++) {
            command.append(" --header=\"").append(escapeShellArg(headers.get(i))).append("\"");
        }

        // Handle request body based on content type
        command.append(handleRequestBody(info, request));

        return command.toString();
    }

    private String handleRequestBody(IRequestInfo info, byte[] request) {
        String contentType = getContentType(info.getHeaders());
        if ("application/json".equals(contentType)) {
            String body = new String(request, info.getBodyOffset(), request.length - info.getBodyOffset(), StandardCharsets.UTF_8);
            return " --data=\"" + escapeShellArg(body) + "\"";
        }

        // Handle other content types or default form parameters
        return handleParameters(info.getParameters());
    }

    private String handleParameters(List<IParameter> parameters) {
        StringBuilder data = new StringBuilder();
        StringJoiner postParams = new StringJoiner("&");

        for (IParameter param : parameters) {
            if (param.getType() == IParameter.PARAM_BODY) {
                String encodedName = URLEncoder.encode(param.getName(), StandardCharsets.UTF_8);
                String encodedValue = URLEncoder.encode(param.getValue(), StandardCharsets.UTF_8);
                postParams.add(encodedName + "=" + encodedValue);
            }
        }

        if (postParams.length() > 0) {
            data.append(" --data=\"").append(postParams.toString()).append("\"");
        }

        return data.toString();
    }

    private String getContentType(List<String> headers) {
        for (String header : headers) {
            if (header.toLowerCase().startsWith("content-type:")) {
                return header.substring(header.indexOf(':') + 1).trim();
            }
        }
        return "";
    }

    private String escapeShellArg(String arg) {
        return arg.replace("\"", "\\\"");
    }
}
