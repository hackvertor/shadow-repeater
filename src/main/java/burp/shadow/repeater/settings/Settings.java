package burp.shadow.repeater.settings;

import burp.IBurpExtenderCallbacks;
import burp.shadow.repeater.ShadowRepeaterExtension;
import burp.shadow.repeater.utils.GridbagUtils;
import burp.shadow.repeater.utils.Utils;
import org.json.JSONObject;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import static burp.shadow.repeater.ShadowRepeaterExtension.*;
import static burp.shadow.repeater.utils.GridbagUtils.addMarginToGbc;
import static burp.shadow.repeater.utils.GridbagUtils.createConstraints;
import static java.awt.GridBagConstraints.CENTER;

public class Settings {
    private JSONObject settings = new JSONObject();
    private JSONObject defaults = new JSONObject();
    private HashMap<String, ArrayList<String>> categories = new HashMap<>();
    private final String settingsName;
    private IBurpExtenderCallbacks callbacks;
    private boolean isModified = false;

    public static void showSettingsWindow() {
        Settings settings = new Settings("general", ShadowRepeaterExtension.callbacks);
        Utils.registerGeneralSettings(settings);
        settings.load();
        JFrame settingsWindow = Utils.getSettingsWindowInstance();
        settingsWindow.getContentPane().removeAll();
        settingsWindow.setTitle(extensionName + " settings");
        settingsWindow.setResizable(false);
        settingsWindow.setPreferredSize(new Dimension(500, 600));
        Container pane = settingsWindow.getContentPane();
        try {
            Map<String, Integer> columns = new HashMap<>();
            columns.put("AI", 1);
            columns.put("Repeater settings", 1);
            JPanel settingsInterface = settings.buildInterface(settingsWindow, 250, 25,10, columns, ShadowRepeaterExtension.generalSettings);
            settingsInterface.setAutoscrolls(true);
            settingsInterface.setPreferredSize(new Dimension(500, 400));
            JScrollPane settingsScroll = new JScrollPane(settingsInterface);
            settingsScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
            settingsScroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
            pane.setLayout(new GridBagLayout());
            JLabel logoLabel;
            logoLabel = new JLabel(Utils.createImageIcon("/images/logo.png", "logo"));
            JPanel logoContainer = new JPanel(new GridBagLayout());
            logoContainer.add(logoLabel, GridbagUtils.createConstraints(0, 0, 1, 1, 0, 0, 0, 0, GridBagConstraints.NORTH));
            JLabel versionLabel = new JLabel(version);
            logoContainer.add(versionLabel, GridbagUtils.createConstraints(0, 1, 1, 1, 0, 0, 0, 0, GridBagConstraints.SOUTH));
            pane.add(logoContainer, addMarginToGbc(createConstraints(0, 0, 1, GridBagConstraints.NONE, 1, 0, 5, 5, GridBagConstraints.NORTHEAST), 5, 5, 5, 5));
            pane.add(settingsScroll, createConstraints(0, 1, 1, GridBagConstraints.BOTH, 1, 1, 5, 5, CENTER));
        } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
            ShadowRepeaterExtension.callbacks.printError("Error building interface:" + e);
            throw new RuntimeException(e);
        }
        settingsWindow.pack();
        settingsWindow.setLocationRelativeTo(null);
        settingsWindow.setVisible(true);
    }

    public enum SettingType  {
            Boolean, String, Password, Integer
    }

    public Settings(String settingsName, IBurpExtenderCallbacks callbacks) {
        this.settingsName = settingsName;
        this.callbacks = callbacks;
    }

    private void addCategory(String category, String name) {
        if(!categories.containsKey(category)){
            categories.put(category, new ArrayList<>());
        }
        categories.get(category).add(name);
    }

    public boolean validate() {
        for (Map.Entry<String, ArrayList<String>> categoryKeySet : categories.entrySet()) {
            for (String name : categoryKeySet.getValue()) {
                if (!this.settings.has(name)) {
                    this.settings.put(name, this.defaults.getJSONObject(name));
                }
                JSONObject currentSetting = this.settings.getJSONObject(name);
                if (currentSetting.getString("type").equals("Integer")) {
                    try {
                        int value = this.getInteger(name);
                        int min = currentSetting.getInt("min");
                        int max = currentSetting.getInt("max");
                        if (value < min || value > max) {
                            api.logging().logToError("Value expects a value between " + min + " and " + max);
                            return false;
                        }
                    } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    public void registerBooleanSetting(String name, boolean defaultValue, String description, String category, String warning) {
        addCategory(category, name);
        JSONObject setting;
        if(this.settings.has(name)) {
            setting = (JSONObject) this.settings.get(name);
        } else {
           setting = new JSONObject();
        }
        setting.put("description", description);
        setting.put("default", defaultValue);
        setting.put("type", "Boolean");
        setting.put("category", category);
        if(warning != null) {
            setting.put("warning", warning);
        }
        this.settings.put(name, setting);
        this.defaults.put(name, setting);
    }
    public void registerStringSetting(String name, String defaultValue, String description, String category) {
        addCategory(category, name);
        JSONObject setting;
        if(this.settings.has(name)) {
            setting = (JSONObject) this.settings.get(name);
        } else {
            setting = new JSONObject();
        }
        setting.put("description", description);
        setting.put("default", defaultValue);
        setting.put("type", "String");
        setting.put("category", category);
        this.settings.put(name, setting);
        this.defaults.put(name, setting);
    }
    public void registerPasswordSetting(String name, String defaultValue, String description, String category) {
        addCategory(category, name);
        JSONObject setting;
        if(this.settings.has(name)) {
            setting = (JSONObject) this.settings.get(name);
        } else {
            setting = new JSONObject();
        }
        setting.put("description", description);
        setting.put("default", defaultValue);
        setting.put("type", "Password");
        setting.put("category", category);
        this.settings.put(name, setting);
        this.defaults.put(name, setting);
    }
    public void registerIntegerSetting(String name, int defaultValue, String description, String category, int min, int max) {
        addCategory(category, name);
        JSONObject setting;
        if(this.settings.has(name)) {
            setting = (JSONObject) this.settings.get(name);
        } else {
            setting = new JSONObject();
        }
        setting.put("description", description);
        setting.put("default", defaultValue);
        setting.put("type", "Integer");
        setting.put("category", category);
        setting.put("min", min);
        setting.put("max", max);
        this.settings.put(name, setting);
        this.defaults.put(name, setting);
    }
    public void load() {
        String json = callbacks.loadExtensionSetting(this.settingsName);
        if(json == null) {
            return;
        }
        this.settings = new JSONObject(json);
    }
    public void save(){
        isModified = false;
        callbacks.saveExtensionSetting(this.settingsName, this.settings.toString());
    }
    public boolean getBoolean(String name) throws UnregisteredSettingException, InvalidTypeSettingException {
        JSONObject setting = this.getSetting(name);
        String type = setting.getString("type");
        if(SettingType.Boolean.name().equals(type)) {
            if(setting.has("value")) {
                return setting.getBoolean("value");
            } else {
                return setting.getBoolean("default");
            }
        }
        throw new InvalidTypeSettingException("The setting " + name + " expects a boolean");
    }

    public String getString(String name) throws UnregisteredSettingException, InvalidTypeSettingException {
        JSONObject setting = this.getSetting(name);
        String type = setting.getString("type");
        if(SettingType.String.name().equals(type) || SettingType.Password.name().equals(type)) {
            if(setting.has("value")) {
                return setting.getString("value");
            } else {
                return setting.getString("default");
            }
        }
        throw new InvalidTypeSettingException("The setting " + name + " expects a string");
    }

    public int getInteger(String name) throws UnregisteredSettingException, InvalidTypeSettingException {
        JSONObject setting = this.getSetting(name);
        String type = setting.getString("type");
        if(SettingType.Integer.name().equals(type)) {
            if(setting.has("value")) {
                return setting.getInt("value");
            } else {
                return setting.getInt("default");
            }
        }
        throw new InvalidTypeSettingException("The setting " + name + " expects a int");
    }

    public void setString(String name, String value) throws UnregisteredSettingException, InvalidTypeSettingException {
        JSONObject setting = this.getSetting(name);
        String type = setting.getString("type");
        if(SettingType.String.name().equals(type) || SettingType.Password.name().equals(type)) {
            setting.put("value", value);
            isModified = true;
            return;
        }
        throw new InvalidTypeSettingException("Error setting " + name + " expects a string");
    }
    public void setInteger(String name, int value) throws UnregisteredSettingException, InvalidTypeSettingException {
        JSONObject setting = this.getSetting(name);
        String type = setting.getString("type");
        if(SettingType.Integer.name().equals(type)) {
            setting.put("value", value);
            isModified = true;
            return;
        }
        throw new InvalidTypeSettingException("Error setting " + name + " expects an int");
    }

    public void setBoolean(String name, boolean value) throws UnregisteredSettingException, InvalidTypeSettingException {
        JSONObject setting = this.getSetting(name);
        String type = setting.getString("type");
        if(SettingType.Boolean.name().equals(type)) {
            setting.put("value", value);
            isModified = true;
            return;
        }
        throw new InvalidTypeSettingException("Error setting " + name + " expects an boolean");
    }

    private JSONObject getSetting(String name) throws UnregisteredSettingException {
        if(!this.settings.has(name) && !this.defaults.has(name)) {
            throw new UnregisteredSettingException(name +" has not been registered.");
        }
        return this.settings.has(name) ? this.settings.getJSONObject(name) : this.defaults.getJSONObject(name);
    }

    private void updateField(String name, JTextField field, JSONObject currentSetting) {
        if(currentSetting.getString("type").equals("String") || currentSetting.getString("type").equals("Password")) {
            try {
                this.setString(name, field.getText());
            } catch (UnregisteredSettingException | InvalidTypeSettingException ex) {
                callbacks.printError(ex.toString());
                throw new RuntimeException(ex);
            }
        } else {
            try {
                int amount = Integer.parseInt(field.getText());
                this.setInteger(name, amount);
            } catch (UnregisteredSettingException | InvalidTypeSettingException ex) {
                callbacks.printError(ex.toString());
            } catch (NumberFormatException ignored) {}
        }
    }
    private void updateBoolean(String name, boolean checked) {
        try {
            this.setBoolean(name, checked);
        } catch (UnregisteredSettingException | InvalidTypeSettingException ex) {
            callbacks.printError(ex.toString());
            throw new RuntimeException(ex);
        }
    }

    private void resetSettings() {
        Iterator<String> keys = this.settings.keys();
        while(keys.hasNext()) {
            String key = keys.next();
            JSONObject setting = (JSONObject) this.settings.get(key);
            if (setting != null) {
                setting.remove("value");
                isModified = true;
            }
        }
    }
    public JPanel buildInterface(JFrame settingsWindow, int componentWidth, int componentHeight, int spacing, Map<String, Integer> columns, Settings loadSettingObject) throws UnregisteredSettingException, InvalidTypeSettingException {
        JPanel settingsPanel = new JPanel(new GridBagLayout());
        JLabel status = new JLabel(" ");
        Settings settings = this;
        JPanel column1 = new JPanel();
        column1.setLayout(new BoxLayout(column1, BoxLayout.Y_AXIS));
        JPanel column2 = new JPanel();
        column2.setLayout(new BoxLayout(column2, BoxLayout.Y_AXIS));
        for (Map.Entry<String, ArrayList<String>> categoryKeySet : categories.entrySet()) {
            String categoryName = categoryKeySet.getKey();
            JPanel categoryContainer = new JPanel();
            categoryContainer.setLayout(new GridBagLayout());
            categoryContainer.setBorder(BorderFactory.createTitledBorder(categoryName));
            int componentRow = 0;
            for (String name : categoryKeySet.getValue()) {
                if(!this.settings.has(name)) {
                    this.settings.put(name, this.defaults.getJSONObject(name));
                }
                JSONObject currentSetting = this.settings.getJSONObject(name);
                switch (currentSetting.getString("type")) {
                    case "Password" -> {
                        JLabel label = new JLabel(currentSetting.getString("description"));
                        label.setPreferredSize(new Dimension(componentWidth, componentHeight));
                        JPasswordField field = new JPasswordField();
                        field.setEchoChar('*');
                        field.setText(this.getString(name));
                        field.setPreferredSize(new Dimension(componentWidth, componentHeight));
                        categoryContainer.add(label, addMarginToGbc(createConstraints(0, componentRow, 1, GridBagConstraints.BOTH, 1, 0, spacing, spacing, GridBagConstraints.WEST), 0, 5, 0, 0));
                        categoryContainer.add(new JLabel(), createConstraints(1, componentRow, 1, GridBagConstraints.BOTH, 1, 0, spacing, spacing, GridBagConstraints.WEST));
                        componentRow++;
                        JPanel passwordContainer = new JPanel(new GridBagLayout());
                        passwordContainer.add(field, createConstraints(0, 0, 2, GridBagConstraints.BOTH, 1, 1, 5, 5, GridBagConstraints.CENTER));
                        JCheckBox checkBox = new JCheckBox();
                        checkBox.addItemListener(e -> {
                            if(e.getStateChange() == ItemEvent.SELECTED) {
                                field.setEchoChar('\u0000');
                            } else {
                                field.setEchoChar('*');
                            }
                        });
                        passwordContainer.add(checkBox, createConstraints(0, 1, 1, GridBagConstraints.WEST, 0, 0, 5, 5, GridBagConstraints.WEST));
                        passwordContainer.add(new JLabel("Show"), createConstraints(1, 1, 1, GridBagConstraints.NONE, 0, 0, 5, 5, GridBagConstraints.WEST));
                        categoryContainer.add(passwordContainer, createConstraints(0, componentRow, 2, GridBagConstraints.BOTH, 1, 0, spacing, spacing, GridBagConstraints.WEST));
                        field.getDocument().addDocumentListener(new DocumentListener() {
                            @Override
                            public void insertUpdate(DocumentEvent e) {
                                settings.updateField(name, field, currentSetting);
                            }

                            @Override
                            public void removeUpdate(DocumentEvent e) {
                                settings.updateField(name, field, currentSetting);
                            }

                            @Override
                            public void changedUpdate(DocumentEvent e) {
                                settings.updateField(name, field, currentSetting);
                            }
                        });
                    }
                    case "Integer", "String" -> {
                        JLabel label = new JLabel(currentSetting.getString("description"));
                        label.setPreferredSize(new Dimension(componentWidth, componentHeight));
                        JTextField field = new JTextField();
                        if(currentSetting.getString("type").equals("String")) {
                            field.setText(this.getString(name));
                        } else {
                            field.setText(this.getInteger(name)+"");
                        }
                        field.setPreferredSize(new Dimension(componentWidth, componentHeight));
                        categoryContainer.add(label, addMarginToGbc(createConstraints(0, componentRow, 1, GridBagConstraints.BOTH, 1, 0, spacing, spacing, GridBagConstraints.WEST), 0, 5, 0,0));
                        categoryContainer.add(new JLabel(), createConstraints(1, componentRow, 1, GridBagConstraints.BOTH, 1, 0, spacing, spacing, GridBagConstraints.WEST));
                        componentRow++;
                        categoryContainer.add(field, createConstraints(0, componentRow, 2, GridBagConstraints.BOTH, 1, 0, spacing, spacing, GridBagConstraints.WEST));
                        field.getDocument().addDocumentListener(new DocumentListener() {
                            @Override
                            public void insertUpdate(DocumentEvent e) {
                                settings.updateField(name, field, currentSetting);
                            }

                            @Override
                            public void removeUpdate(DocumentEvent e) {
                                settings.updateField(name, field, currentSetting);
                            }

                            @Override
                            public void changedUpdate(DocumentEvent e) {
                                settings.updateField(name, field, currentSetting);
                            }
                        });
                    }
                    case "Boolean" -> {
                        JSONObject defaultSetting = this.defaults.getJSONObject(name);
                        boolean shouldWarn = defaultSetting.has("warning");
                        JLabel label = new JLabel(currentSetting.getString("description"));
                        label.setPreferredSize(new Dimension(componentWidth, componentHeight));
                        JCheckBox checkBox = new JCheckBox();
                        checkBox.setSelected(this.getBoolean(name));
                        checkBox.addActionListener(e -> {
                            boolean isChecked = checkBox.isSelected();
                            if(isChecked && shouldWarn) {
                                int confirm = JOptionPane.showConfirmDialog(checkBox, defaultSetting.getString("warning"));
                                if(confirm != 0) {
                                    checkBox.setSelected(false);
                                    isChecked = false;
                                }
                            }
                            this.updateBoolean(name, isChecked);
                        });
                        categoryContainer.add(label, addMarginToGbc(createConstraints(0, componentRow, 1, GridBagConstraints.BOTH, 1, 0, spacing, spacing, GridBagConstraints.WEST), 0, 5, 0,0));
                        categoryContainer.add(checkBox, createConstraints(1, componentRow, 1, GridBagConstraints.EAST, 0, 0, spacing, spacing, GridBagConstraints.EAST));
                    }
                    default -> {
                        throw new InvalidTypeSettingException("Unexpected type");
                    }
                }
                componentRow++;
            }
            int col = columns.get(categoryName);
            if(col == 1) {
                column1.add(categoryContainer);
                column1.add(Box.createVerticalStrut(10));
            } else {
                column2.add(categoryContainer);
                column2.add(Box.createVerticalStrut(10));
            }
        }

        settingsPanel.add(column1, addMarginToGbc(createConstraints(0, 1, 1, GridBagConstraints.HORIZONTAL, 1, 0, spacing, spacing, GridBagConstraints.NORTHWEST), 5, 5, 5, 5));
        settingsPanel.add(column2, addMarginToGbc(createConstraints(1, 1, 1, GridBagConstraints.HORIZONTAL, 1, 0, spacing, spacing, GridBagConstraints.NORTHWEST), 5, 5, 5, 5));
        JPanel buttonsContainer = new JPanel(new GridBagLayout());
        JButton closeSettingsBtn = new JButton("Close");
        JButton resetSettingsBtn = new JButton("Reset");
        resetSettingsBtn.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(null, "Are you sure you want to reset your settings?");
            if(confirm == 0) {
                this.resetSettings();
                this.save();
                loadSettingObject.load();
                status.setText("Successfully reset settings. Close to complete.");

            }
        });
        JButton updateSettingsBtn = new JButton("Update");
        updateSettingsBtn.addActionListener(e -> {
            if(!this.validate()) {
                status.setText("Error saving settings. Invalid values.");
                status.setOpaque(true);
                status.setBackground(Color.decode("#dc2626"));
                status.setBorder(new EmptyBorder(5, 5, 5, 5));
                return;
            }
            status.setBorder(null);
            status.setOpaque(false);
            status.setBackground(null);
            this.save();
            loadSettingObject.load();
            status.setText("Successfully updated settings.");
        });
        int containerRow = 2;
        buttonsContainer.add(new Label(), GridbagUtils.createConstraints(0, 0, 1, GridBagConstraints.BOTH, 0, 0, 5, 5, CENTER));
        buttonsContainer.add(closeSettingsBtn, GridbagUtils.addMarginToGbc(GridbagUtils.createConstraints(1, 0, 1, GridBagConstraints.NONE, 0, 0, 5, 5, CENTER), 2, 2, 2, 2));
        buttonsContainer.add(resetSettingsBtn, GridbagUtils.addMarginToGbc(GridbagUtils.createConstraints(2, 0, 1, GridBagConstraints.NONE, 0, 0, 5, 5, CENTER), 2, 2, 2, 2));
        buttonsContainer.add(updateSettingsBtn, GridbagUtils.addMarginToGbc(GridbagUtils.createConstraints(3, 0, 1, GridBagConstraints.NONE, 0, 0, 5, 5, CENTER), 2, 2, 2, 2));
        buttonsContainer.add(new Label(), GridbagUtils.createConstraints(4, 0, 1, GridBagConstraints.BOTH, 0, 0, 5, 5, CENTER));
        closeSettingsBtn.addActionListener(e -> {
            if(isModified) {
                int confirm = JOptionPane.showConfirmDialog(null, "Are you sure you have unsaved settings?");
                if(confirm != 0) {
                    return;
                }
            }
            settingsWindow.setVisible(false);
            settingsWindow.getContentPane().removeAll();
        });
        buttonsContainer.add(status, GridbagUtils.addMarginToGbc(GridbagUtils.createConstraints(0, 1, 5, GridBagConstraints.NONE, 0, 0, 5, 5, CENTER), 2, 2, 2, 2));
        settingsPanel.add(buttonsContainer, createConstraints(0, containerRow, 2, GridBagConstraints.NONE, 0, 0, spacing, spacing, GridBagConstraints.CENTER));
        settingsWindow.pack();
        settingsWindow.setLocationRelativeTo(null);
        settingsWindow.setVisible(true);
        return settingsPanel;
    }
}
