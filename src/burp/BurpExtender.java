package burp;

import java.awt.Component;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;

/**
 * @author Joaquin R. Martinez
 */
public class BurpExtender implements IBurpExtender, IHttpListener {

    private IBurpExtenderCallbacks ibec;
    private UInterface uInterface;
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks ibec) {
        this.ibec = ibec;//guardar
        helpers = ibec.getHelpers();
        uInterface = new UInterface(ibec);
        ibec.registerHttpListener(this);
        /*agregar el nuevo tab a burp*/
        ibec.addSuiteTab(new ITab() {
            @Override
            public String getTabCaption() {
                return "Hashes";
            }

            @Override
            public Component getUiComponent() {
                return uInterface;
            }
        });
    }

    @Override
    public void processHttpMessage(int flag, boolean isRequest, IHttpRequestResponse message) {
        if (!isRequest && (IBurpExtenderCallbacks.TOOL_PROXY == flag
                || IBurpExtenderCallbacks.TOOL_SPIDER == flag)
                && ibec.isInScope(message.getUrl())) {
            try {
                LinkedList<Item> items = new Hash().getItems();
                LinkedList<Item> reflectedItems = new LinkedList();
                for (Item item : items) {
                    if (isReflected(item.getValue(), message.getResponse())) {
                        reflectedItems.add(item);
                    }
                }                
                if (reflectedItems.size()>0) {
                    uInterface.sendToRequestsTable(message, reflectedItems);
                }
            } catch (NoSuchAlgorithmException ex) {
                ibec.printError(ex.toString());
            }            
        }
    }

    private boolean isReflected(String param, byte[] response) {
        int indexOf = helpers.indexOf(response, helpers.stringToBytes(param),
                true, 0, response.length - 1);
        if (indexOf != -1) {
            return true;
        }
        return false;
    }

}
