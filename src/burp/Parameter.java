
package burp;

import burp.IParameter;

/**
 * Implementation of {@link IParameter} interface
 *
 * @author Joaquin R. Martinez
 */
public class Parameter implements IParameter {

    private String name;
    protected String value;
    protected byte type;
    public static final byte PARAM_HEADER = 8;

    public void setName(String name) {
        this.name = name;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public Parameter(String name, String value, byte type) {
        this.name = name.trim();
        this.value = value.trim();
        this.type = type;
    }
    
    public Parameter(IParameter param){
        this(param.getName(), param.getValue(), param.getType());
    }

    public Parameter() {
        this.name = "";
        this.value = "";
    }
    
    @Override
    public byte getType() {
        return this.type;
    }
    
    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public String getValue() {
        return this.value;
    }

    @Override
    public int getNameStart() {
        return toString().indexOf(this.name);
    }

    @Override
    public int getNameEnd() {
        return getNameStart() + this.name.length();
    }

    @Override
    public int getValueStart() {
        return toString().indexOf(this.getValue());
    }

    @Override
    public int getValueEnd() {
        return getValueStart() + this.value.length();
    }
    
}
