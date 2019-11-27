package com.alternadom.wifiiot;

import android.Manifest;
import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.net.wifi.SupplicantState;
import android.os.Handler;
import android.os.Looper;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.NetworkRequest;
import android.net.Uri;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.provider.Settings;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import info.whitebyte.hotspotmanager.ClientScanResult;
import info.whitebyte.hotspotmanager.FinishScanListener;
import info.whitebyte.hotspotmanager.WifiApManager;
import io.flutter.plugin.common.EventChannel;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;
import io.flutter.plugin.common.PluginRegistry.Registrar;
import io.flutter.plugin.common.PluginRegistry.ViewDestroyListener;
import io.flutter.view.FlutterNativeView;

/**
 * WifiIotPlugin
 */
public class WifiIotPlugin implements MethodCallHandler, EventChannel.StreamHandler {
  private static final String TAG = "WifiIotPlugin";
  private WifiManager moWiFi;
    private Context moContext;
    private WifiApManager moWiFiAPManager;
    private Activity moActivity;
    private BroadcastReceiver receiver;
    private List<String> ssidsToBeRemovedOnExit = new ArrayList<String>();

    private WifiIotPlugin(Activity poActivity) {
        this.moActivity = poActivity;
        this.moContext = poActivity.getApplicationContext();
        this.moWiFi = (WifiManager) moContext.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        this.moWiFiAPManager = new WifiApManager(moContext.getApplicationContext());
    }

    /**
     * Plugin registration.
     */
    public static void registerWith(Registrar registrar) {
        if (registrar.activity() == null) {
            // When a background flutter view tries to register the plugin, the registrar has no activity.
            // We stop the registration process as this plugin is foreground only.
            return;
        }
        final MethodChannel channel = new MethodChannel(registrar.messenger(), "wifi_iot");
        final EventChannel eventChannel = new EventChannel(registrar.messenger(), "plugins.wififlutter.io/wifi_scan");
        final WifiIotPlugin wifiIotPlugin = new WifiIotPlugin(registrar.activity());
        eventChannel.setStreamHandler(wifiIotPlugin);
        channel.setMethodCallHandler(wifiIotPlugin);

        registrar.addViewDestroyListener(new ViewDestroyListener() {
            @Override
            public boolean onViewDestroy(FlutterNativeView view) {
                if (!wifiIotPlugin.ssidsToBeRemovedOnExit.isEmpty()) {
                    List<WifiConfiguration> wifiConfigList =
                            wifiIotPlugin.moWiFi.getConfiguredNetworks();
                    for (String ssid : wifiIotPlugin.ssidsToBeRemovedOnExit) {
                        for (WifiConfiguration wifiConfig : wifiConfigList) {
                            if (wifiConfig.SSID.equals(ssid)) {
                                wifiIotPlugin.moWiFi.removeNetwork(wifiConfig.networkId);
                            }
                        }
                    }
                }
                return false;
            }
        });
    }

    @Override
    public void onMethodCall(MethodCall poCall, Result poResult) {
        switch (poCall.method) {
            case "loadWifiList":
                loadWifiList(poResult);
                break;
            case "forceWifiUsage":
                forceWifiUsage(poCall, poResult);
                break;
            case "isEnabled":
                isEnabled(poResult);
                break;
            case "setEnabled":
                setEnabled(poCall, poResult);
                break;
            case "connect":
                connect(poCall, poResult);
                break;
            case "findAndConnect":
                findAndConnect(poCall, poResult);
                break;
            case "isConnected":
                isConnected(poResult);
                break;
            case "disconnect":
                disconnect(poResult);
                break;
            case "getSSID":
                getSSID(poResult);
                break;
            case "getBSSID":
                getBSSID(poResult);
                break;
            case "getCurrentSignalStrength":
                getCurrentSignalStrength(poResult);
                break;
            case "getFrequency":
                getFrequency(poResult);
                break;
            case "getIP":
                getIP(poResult);
                break;
            case "removeWifiNetwork":
                removeWifiNetwork(poCall, poResult);
                break;
            case "isRegisteredWifiNetwork":
                isRegisteredWifiNetwork(poCall, poResult);
                break;
            case "isWiFiAPEnabled":
                isWiFiAPEnabled(poResult);
                break;
            case "setWiFiAPEnabled":
                setWiFiAPEnabled(poCall, poResult);
                break;
            case "getWiFiAPState":
                getWiFiAPState(poResult);
                break;
            case "getClientList":
                getClientList(poCall, poResult);
                break;
            case "getWiFiAPSSID":
                getWiFiAPSSID(poResult);
                break;
            case "setWiFiAPSSID":
                setWiFiAPSSID(poCall, poResult);
                break;
            case "isSSIDHidden":
                isSSIDHidden(poResult);
                break;
            case "setSSIDHidden":
                setSSIDHidden(poCall, poResult);
                break;
            case "getWiFiAPPreSharedKey":
                getWiFiAPPreSharedKey(poResult);
                break;
            case "setWiFiAPPreSharedKey":
                setWiFiAPPreSharedKey(poCall, poResult);
                break;
            case "setMACFiltering":
                setMACFiltering(poCall, poResult);
                break;
            default:
                poResult.notImplemented();
                break;
        }
    }

    /**
     *
     * @param poCall
     * @param poResult
     */
    private void setMACFiltering(MethodCall poCall, Result poResult) {
//        String sResult = sudoForResult("iptables --list");
//        Log.d(this.getClass().toString(), sResult);
        boolean bEnable = poCall.argument("state");


        /// cat /data/misc/wifi_hostapd/hostapd.accept

        Log.e(this.getClass().toString(), "TODO : Develop function to enable/disable MAC filtering...");

        poResult.error("TODO", "Develop function to enable/disable MAC filtering...", null);
    }


    /**
     * The network's SSID. Can either be an ASCII string,
     * which must be enclosed in double quotation marks
     * (e.g., {@code "MyNetwork"}), or a string of
     * hex digits, which are not enclosed in quotes
     * (e.g., {@code 01a243f405}).
     */
    private void getWiFiAPSSID(Result poResult) {
        WifiConfiguration oWiFiConfig = moWiFiAPManager.getWifiApConfiguration();
        String sAPSSID = oWiFiConfig.SSID;
        poResult.success(sAPSSID);
    }

    private void setWiFiAPSSID(MethodCall poCall, Result poResult) {
        String sAPSSID = poCall.argument("ssid");

        WifiConfiguration oWiFiConfig = moWiFiAPManager.getWifiApConfiguration();

        oWiFiConfig.SSID = sAPSSID;

        moWiFiAPManager.setWifiApConfiguration(oWiFiConfig);

        poResult.success(null);
    }

    /**
     * This is a network that does not broadcast its SSID, so an
     * SSID-specific probe request must be used for scans.
     */
    private void isSSIDHidden(Result poResult) {
        WifiConfiguration oWiFiConfig = moWiFiAPManager.getWifiApConfiguration();
        boolean isSSIDHidden = oWiFiConfig.hiddenSSID;
        poResult.success(isSSIDHidden);
    }

    private void setSSIDHidden(MethodCall poCall, Result poResult) {
        boolean isSSIDHidden = poCall.argument("hidden");

        WifiConfiguration oWiFiConfig = moWiFiAPManager.getWifiApConfiguration();

        Log.d(this.getClass().toString(), "isSSIDHidden : " + isSSIDHidden);
        oWiFiConfig.hiddenSSID = isSSIDHidden;

        moWiFiAPManager.setWifiApConfiguration(oWiFiConfig);

        poResult.success(null);
    }

    /**
     * Pre-shared key for use with WPA-PSK. Either an ASCII string enclosed in
     * double quotation marks (e.g., {@code "abcdefghij"} for PSK passphrase or
     * a string of 64 hex digits for raw PSK.
     * <p/>
     * When the value of this key is read, the actual key is
     * not returned, just a "*" if the key has a value, or the null
     * string otherwise.
     */
    private void getWiFiAPPreSharedKey(Result poResult) {
        WifiConfiguration oWiFiConfig = moWiFiAPManager.getWifiApConfiguration();
        String sPreSharedKey = oWiFiConfig.preSharedKey;
        poResult.success(sPreSharedKey);
    }

    private void setWiFiAPPreSharedKey(MethodCall poCall, Result poResult) {
        String sPreSharedKey = poCall.argument("preSharedKey");

        WifiConfiguration oWiFiConfig = moWiFiAPManager.getWifiApConfiguration();

        oWiFiConfig.preSharedKey = sPreSharedKey;

        moWiFiAPManager.setWifiApConfiguration(oWiFiConfig);

        poResult.success(null);
    }

    /**
     * Gets a list of the clients connected to the Hotspot
     * *** getClientList :
     * param onlyReachables   {@code false} if the list should contain unreachable (probably disconnected) clients, {@code true} otherwise
     * param reachableTimeout Reachable Timout in miliseconds, 300 is default
     * param finishListener,  Interface called when the scan method finishes
     */
    private void getClientList(MethodCall poCall, final Result poResult) {
        Boolean onlyReachables = false;
        if (poCall.argument("onlyReachables") != null) {
            onlyReachables = poCall.argument("onlyReachables");
        }

        Integer reachableTimeout = 300;
        if (poCall.argument("reachableTimeout") != null) {
            reachableTimeout = poCall.argument("reachableTimeout");
        }

        final Boolean finalOnlyReachables = onlyReachables;
        FinishScanListener oFinishScanListener = new FinishScanListener() {
            @Override
            public void onFinishScan(final ArrayList<ClientScanResult> clients) {
                try {
                    JSONArray clientArray = new JSONArray();

                    for (ClientScanResult client : clients) {
                        JSONObject clientObject = new JSONObject();

                        Boolean clientIsReachable = client.isReachable();
                        Boolean shouldReturnCurrentClient = true;
                        if ( finalOnlyReachables.booleanValue()) {
                            if (!clientIsReachable.booleanValue()){
                                shouldReturnCurrentClient = Boolean.valueOf(false);
                            }
                        }
                        if (shouldReturnCurrentClient.booleanValue()) {
                            try {
                                clientObject.put("IPAddr", client.getIpAddr());
                                clientObject.put("HWAddr", client.getHWAddr());
                                clientObject.put("Device", client.getDevice());
                                clientObject.put("isReachable", client.isReachable());
                            } catch (JSONException e) {
                                poResult.error("Exception", e.getMessage(), null);
                            }
                            clientArray.put(clientObject);
                        }
                    }
                    poResult.success(clientArray.toString());
                } catch (Exception e) {
                    poResult.error("Exception", e.getMessage(), null);
                }
            }
        };

        if (reachableTimeout != null) {
            moWiFiAPManager.getClientList(onlyReachables, reachableTimeout, oFinishScanListener);
        } else {
            moWiFiAPManager.getClientList(onlyReachables, oFinishScanListener);
        }
    }

    /**
     * Return whether Wi-Fi AP is enabled or disabled.
     * *** isWifiApEnabled :
     * return {@code true} if Wi-Fi AP is enabled
     */
    private void isWiFiAPEnabled(Result poResult) {
        poResult.success(moWiFiAPManager.isWifiApEnabled());
    }

    /**
     * Start AccessPoint mode with the specified
     * configuration. If the radio is already running in
     * AP mode, update the new configuration
     * Note that starting in access point mode disables station
     * mode operation
     * *** setWifiApEnabled :
     * param wifiConfig SSID, security and channel details as part of WifiConfiguration
     * return {@code true} if the operation succeeds, {@code false} otherwise
     */
    private void setWiFiAPEnabled(MethodCall poCall, Result poResult) {
        boolean enabled = poCall.argument("state");
        moWiFiAPManager.setWifiApEnabled(null, enabled);
        poResult.success(null);
    }

    /**
     * Gets the Wi-Fi enabled state.
     * *** getWifiApState :
     * return {link WIFI_AP_STATE}
     */
    private void getWiFiAPState(Result poResult) {
        poResult.success(moWiFiAPManager.getWifiApState().ordinal());
    }

    @Override
    public void onListen(Object o, EventChannel.EventSink eventSink) {
        int PERMISSIONS_REQUEST_CODE_ACCESS_COARSE_LOCATION = 65655434;
        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && moContext.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED){
            moActivity.requestPermissions(new String[]{Manifest.permission.ACCESS_COARSE_LOCATION}, PERMISSIONS_REQUEST_CODE_ACCESS_COARSE_LOCATION);
        }
        receiver = createReceiver(eventSink);

        moContext.registerReceiver(receiver, new IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION));
    }

    @Override
    public void onCancel(Object o) {
        if(receiver != null){
            moContext.unregisterReceiver(receiver);
            receiver = null;
        }

    }

    private BroadcastReceiver createReceiver(final EventChannel.EventSink eventSink){
        return new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                eventSink.success(handleNetworkScanResult().toString());
            }
        };
    }
    JSONArray handleNetworkScanResult(){
        List<ScanResult> results = moWiFi.getScanResults();
        JSONArray wifiArray = new JSONArray();

        Log.d("got wifiIotPlugin", "result number of SSID: "+ results.size());
        try {
            for (ScanResult result : results) {
                JSONObject wifiObject = new JSONObject();
                if (!result.SSID.equals("")) {

                    wifiObject.put("SSID", result.SSID);
                    wifiObject.put("BSSID", result.BSSID);
                    wifiObject.put("capabilities", result.capabilities);
                    wifiObject.put("frequency", result.frequency);
                    wifiObject.put("level", result.level);
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                        wifiObject.put("timestamp", result.timestamp);
                    } else {
                        wifiObject.put("timestamp", 0);
                    }
                    /// Other fields not added
                    //wifiObject.put("operatorFriendlyName", result.operatorFriendlyName);
                    //wifiObject.put("venueName", result.venueName);
                    //wifiObject.put("centerFreq0", result.centerFreq0);
                    //wifiObject.put("centerFreq1", result.centerFreq1);
                    //wifiObject.put("channelWidth", result.channelWidth);

                    wifiArray.put(wifiObject);
                }
            }
        } catch (JSONException e) {
            e.printStackTrace();
        } finally {
            Log.d("got wifiIotPlugin", "final result: "+ results.toString());
            return wifiArray;
        }
    }

    /// Method to load wifi list into string via Callback. Returns a stringified JSONArray
    private void loadWifiList(final Result poResult) {
        try {

            int PERMISSIONS_REQUEST_CODE_ACCESS_COARSE_LOCATION = 65655434;
            if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && moContext.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED){
                moActivity.requestPermissions(new String[]{Manifest.permission.ACCESS_COARSE_LOCATION}, PERMISSIONS_REQUEST_CODE_ACCESS_COARSE_LOCATION);
            }

            moWiFi.startScan();

            poResult.success(handleNetworkScanResult().toString());

        } catch (Exception e) {
            poResult.error("Exception", e.getMessage(), null);
        }
    }


    /// Method to force wifi usage if the user needs to send requests via wifi
    /// if it does not have internet connection. Useful for IoT applications, when
    /// the app needs to communicate and send requests to a device that have no
    /// internet connection via wifi.

    /// Receives a boolean to enable forceWifiUsage if true, and disable if false.
    /// Is important to enable only when communicating with the device via wifi
    /// and remember to disable it when disconnecting from device.
    private void forceWifiUsage(MethodCall poCall, Result poResult) {
        boolean canWriteFlag = false;

        boolean useWifi = poCall.argument("useWifi");

        if (useWifi) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    canWriteFlag = Settings.System.canWrite(moContext);

                    if (!canWriteFlag) {
                        Intent intent = new Intent(Settings.ACTION_MANAGE_WRITE_SETTINGS);
                        intent.setData(Uri.parse("package:" + moContext.getPackageName()));
                        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

                        moContext.startActivity(intent);
                    }
                }


                if (((Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) && canWriteFlag) || ((Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) && !(Build.VERSION.SDK_INT >= Build.VERSION_CODES.M))) {
                    final ConnectivityManager manager = (ConnectivityManager) moContext
                            .getSystemService(Context.CONNECTIVITY_SERVICE);
                    NetworkRequest.Builder builder;
                    builder = new NetworkRequest.Builder();
                    /// set the transport type do WIFI
                    builder.addTransportType(NetworkCapabilities.TRANSPORT_WIFI);

                    if (manager != null) {
                        manager.requestNetwork(builder.build(), new ConnectivityManager.NetworkCallback() {
                            @Override
                            public void onAvailable(Network network) {
                                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                    manager.bindProcessToNetwork(network);
                                    manager.unregisterNetworkCallback(this);
                                } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                                    ConnectivityManager.setProcessDefaultNetwork(network);
                                    manager.unregisterNetworkCallback(this);
                                }
                            }
                        });
                    }
                }
            }
        } else {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                ConnectivityManager manager = (ConnectivityManager) moContext
                        .getSystemService(Context.CONNECTIVITY_SERVICE);
                assert manager != null;
                manager.bindProcessToNetwork(null);
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                ConnectivityManager.setProcessDefaultNetwork(null);
            }
        }
        poResult.success(null);
    }

    /// Method to check if wifi is enabled
    private void isEnabled(Result poResult) {
        poResult.success(moWiFi.isWifiEnabled());
    }

    /// Method to connect/disconnect wifi service
    private void setEnabled(MethodCall poCall, Result poResult) {
        Boolean enabled = poCall.argument("state");
        moWiFi.setWifiEnabled(enabled);
        poResult.success(null);
    }

    private void connect(final MethodCall poCall, final Result poResult) {
        new Thread() {
            public void run() {
                String ssid = poCall.argument("ssid");
                String password = poCall.argument("password");
                String security = poCall.argument("security");
                Boolean joinOnce = poCall.argument("join_once");

                final boolean connected = connectTo(ssid, password, security, joinOnce);
                
				final Handler handler = new Handler(Looper.getMainLooper());
                handler.post(new Runnable() {
                    @Override
                    public void run () {
                        poResult.success(connected);
                    }
                });
            }
        }.start();
    }

    /// Send the ssid and password of a Wifi network into this to connect to the network.
    /// Example:  wifi.findAndConnect(ssid, password);
    /// After 10 seconds, a post telling you whether you are connected will pop up.
    /// Callback returns true if ssid is in the range
    private void findAndConnect(final MethodCall poCall, final Result poResult) {
        int PERMISSIONS_REQUEST_CODE_ACCESS_COARSE_LOCATION = 65655434;
        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && moContext.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED){
            moActivity.requestPermissions(new String[]{Manifest.permission.ACCESS_COARSE_LOCATION}, PERMISSIONS_REQUEST_CODE_ACCESS_COARSE_LOCATION);
        }
        new Thread() {
            public void run() {
                String ssid = poCall.argument("ssid");
                String password = poCall.argument("password");
                Boolean joinOnce = poCall.argument("join_once");

                String security = null;
                List<ScanResult> results = moWiFi.getScanResults();
                for (ScanResult result : results) {
                    String resultString = "" + result.SSID;
                    if (ssid.equals(resultString)) {
                        security = getSecurityType(result);
                    }
                }

                final boolean connected = connectTo(ssid, password, security, joinOnce);

				final Handler handler = new Handler(Looper.getMainLooper());
                handler.post(new Runnable() {
                    @Override
                    public void run () {
                        poResult.success(connected);
                    }
                });
            }
        }.start();
    }

    private static String getSecurityType(ScanResult scanResult) {
        String capabilities = scanResult.capabilities;

        if (capabilities.contains("WPA") ||
                capabilities.contains("WPA2") ||
                capabilities.contains("WPA/WPA2 PSK")) {
            return "WPA";
        } else if (capabilities.contains("WEP")) {
            return "WEP";
        } else {
            return null;
        }
    }

    /// Use this method to check if the device is currently connected to Wifi.
    private void isConnected(Result poResult) {
        ConnectivityManager connManager = (ConnectivityManager) moContext.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo mWifi = connManager != null ? connManager.getNetworkInfo(ConnectivityManager.TYPE_WIFI) : null;
        if (mWifi != null && mWifi.isConnected()) {
            poResult.success(true);
        } else {
            poResult.success(false);
        }
    }

    /// Disconnect current Wifi.
    private void disconnect(Result poResult) {
        moWiFi.disconnect();
        poResult.success(null);
    }

    /// This method will return current ssid
    private void getSSID(Result poResult) {
        WifiInfo info = moWiFi.getConnectionInfo();

        // This value should be wrapped in double quotes, so we need to unwrap it.
        String ssid = info.getSSID();
        if (ssid.startsWith("\"") && ssid.endsWith("\"")) {
            ssid = ssid.substring(1, ssid.length() - 1);
        }

        poResult.success(ssid);
    }

    /// This method will return the basic service set identifier (BSSID) of the current access point
    private void getBSSID(Result poResult) {
        WifiInfo info = moWiFi.getConnectionInfo();

        String bssid = info.getBSSID();

        try {
            poResult.success(bssid.toUpperCase());
        } catch (Exception e) {
            poResult.error("Exception", e.getMessage(), null);
        }
    }

    /// This method will return current WiFi signal strength
    private void getCurrentSignalStrength(Result poResult) {
        int linkSpeed = moWiFi.getConnectionInfo().getRssi();
        poResult.success(linkSpeed);
    }

    /// This method will return current WiFi frequency
    private void getFrequency(Result poResult) {
        WifiInfo info = moWiFi.getConnectionInfo();
        int frequency = 0;
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.LOLLIPOP) {
            frequency = info.getFrequency();
        }
        poResult.success(frequency);
    }

    /// This method will return current IP
    private void getIP(Result poResult) {
        WifiInfo info = moWiFi.getConnectionInfo();
        String stringip = longToIP(info.getIpAddress());
        poResult.success(stringip);
    }

    /// This method will remove the WiFi network as per the passed SSID from the device list
    private void removeWifiNetwork(MethodCall poCall, Result poResult) {
        String prefix_ssid = poCall.argument("ssid");
        if (prefix_ssid.equals("")) {
            poResult.error("Error", "No prefix SSID was given!", null);
        }

        List<WifiConfiguration> mWifiConfigList = moWiFi.getConfiguredNetworks();
        for (WifiConfiguration wifiConfig : mWifiConfigList) {
            String comparableSSID = ('"' + prefix_ssid); //Add quotes because wifiConfig.SSID has them
            if (wifiConfig.SSID.startsWith(comparableSSID)) {
                moWiFi.removeNetwork(wifiConfig.networkId);
                moWiFi.saveConfiguration();
                poResult.success(true);
                return;
            }
        }
        poResult.success(false);
    }

    /// This method will remove the WiFi network as per the passed SSID from the device list
    private void isRegisteredWifiNetwork(MethodCall poCall, Result poResult) {

        String ssid = poCall.argument("ssid");

        List<WifiConfiguration> mWifiConfigList = moWiFi.getConfiguredNetworks();
        String comparableSSID = ('"' + ssid + '"'); //Add quotes because wifiConfig.SSID has them
        if (mWifiConfigList != null) {
            for (WifiConfiguration wifiConfig : mWifiConfigList) {
                if (wifiConfig.SSID.equals(comparableSSID)) {
                    poResult.success(true);
                    return;
                }
            }
        }
        poResult.success(false);
    }

    private static String longToIP(int longIp) {
        StringBuilder sb = new StringBuilder("");
        String[] strip = new String[4];
        strip[3] = String.valueOf((longIp >>> 24));
        strip[2] = String.valueOf((longIp & 0x00FFFFFF) >>> 16);
        strip[1] = String.valueOf((longIp & 0x0000FFFF) >>> 8);
        strip[0] = String.valueOf((longIp & 0x000000FF));
        sb.append(strip[0]);
        sb.append(".");
        sb.append(strip[1]);
        sb.append(".");
        sb.append(strip[2]);
        sb.append(".");
        sb.append(strip[3]);
        return sb.toString();
    }


//  public BitSet getAuthAlgorithm() {
//    BitSet bs = new BitSet(3);
//    bs.clear();
//
//    String[] modes = {"OPEN", "SHARED", "LEAP"};
//    for (int i = modes.length - 1; i >= 0; i--) {
//      if (capability.contains(modes[i])) {
//        bs.set(i);
//      }
//    }
//
//    if (capability.contains("WEP")) {
//      bs.set(0);
//      bs.set(1);
//    }
//    return bs;
//  }
//
//  public BitSet getGroupCiphers() {
//    BitSet bs = new BitSet(4);
//    bs.clear();
//    //String[] modes = { "WEP40", "WEP104","TKIP","CCMP"};
//    String[] modes = {"WEP", "WEP", "TKIP", "CCMP"};
//    for (int i = modes.length - 1; i >= 0; i--) {
//      if (capability.contains(modes[i])) {
//        bs.set(i);
//      }
//    }
//    return bs;
//  }
//
//
//  public BitSet getProtocols() {
//    BitSet bs = new BitSet(2);
//    bs.clear();
//    String[] modes = {"WPA", "RSN"};
//    for (int i = modes.length - 1; i >= 0; i--) {
//      if (capability.contains(modes[i])) {
//        bs.set(i);
//      }
//    }
//
//    if (capability.contains("WPA")) {
//      bs.set(1);//add "RSN"
//    }
//
//    return bs;
//  }


  private WifiConfiguration findCameraAP(String checkSSID) {
    List<WifiConfiguration> wcs = moWiFi.getConfiguredNetworks();
    //AA-1453:
    // Check whether wcs is null or not
    if (wcs != null && wcs.size() > 0) {
      for (WifiConfiguration wc : wcs) {
        // note that: WifiConfiguration SSID has quotes
        if (wc.SSID == null) {
          continue;
        }
        if (wc.SSID.equalsIgnoreCase(checkSSID)) {
          return wc;
        }
      }
    }
    return null;
  }

  private WifiConfiguration buildWifiConfiguration(String checkSSID) {
    WifiConfiguration newWC = new WifiConfiguration();
//    newWC.hiddenSSID = false;
    newWC.SSID = checkSSID;
//    newWC.BSSID = checkBSSID;
//    newWC.status = WifiConfiguration.Status.ENABLED;
    // the following is the settings
    // that found to be working for ai-ball
//    newWC.hiddenSSID = false;
//    newWC.allowedAuthAlgorithms = ns.getAuthAlgorithm();
//    newWC.allowedGroupCiphers = ns.getGroupCiphers();
//    newWC.allowedKeyManagement = ns.getKeyManagement();
//    if (ns.security.equalsIgnoreCase("WPA")) {
//      newWC.preSharedKey = convertToQuotedString(PublicDefineGlob.DEFAULT_WPA_PRESHAREDKEY);
//    }
//    newWC.allowedPairwiseCiphers = ns.getPairWiseCiphers();
//    newWC.allowedProtocols = ns.getProtocols();
    return newWC;
  }

    /// Method to connect to WIFI Network
    private Boolean connectTo(String ssid, String password, String security, Boolean joinOnce) {
        /// Make new configuration
      String checkSSID = '\"' + ssid + '\"';
      WifiConfiguration conf = findCameraAP(checkSSID);
      if (conf == null) {
        Log.d(TAG, "WifiConfiguration conf return null");
        conf=buildWifiConfiguration(checkSSID);
        if(conf == null){
          Log.d(TAG, "WifiConfiguration conf initial  null");
          return false;
        }
      }

      if (security != null) security = security.toUpperCase();
      else security = "NONE";

      if (security.equals("NONE")) {
//        conf.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);

      } else {
        conf.preSharedKey = ssidFormat(password);
        conf.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN);
        conf.allowedProtocols.set(WifiConfiguration.Protocol.WPA); // For WPA
        conf.allowedProtocols.set(WifiConfiguration.Protocol.RSN); // For WPA2
        conf.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK);
        conf.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_EAP);
        conf.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);
        conf.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
        conf.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
        conf.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
      }


        if (joinOnce != null && joinOnce.booleanValue()) {
            ssidsToBeRemovedOnExit.add(conf.SSID);
        }


      int networkId = getNetworkId(conf.SSID);
      Log.d(TAG, "network id found: " + networkId);
      if (networkId == -1) {
        networkId = moWiFi.addNetwork(conf);
        Log.d(TAG, "networkId now: " + networkId);
      }
      if (networkId != -1) {
        if(connectWifiManager(networkId,checkSSID)){
          retryTimes=0;
          return checkConnected();
        }
      }
      Log.d(TAG, "badly...........");
        return false;
    }

    int retryTimes=0;
    private Boolean checkConnected() {
      ConnectivityManager connManager = (ConnectivityManager) moContext.getSystemService(Context.CONNECTIVITY_SERVICE);
      NetworkInfo mWifi = connManager != null ? connManager.getNetworkInfo(ConnectivityManager.TYPE_WIFI) : null;
      if (mWifi != null && mWifi.isConnected()) {
        Log.d(TAG, "checkConnected");
        WifiInfo info = moWiFi.getConnectionInfo();
        String stringip = longToIP(info.getIpAddress());
        Log.d(TAG, "stringip:  " + stringip);
          return true;
      } else {
        if (retryTimes<4) {
          Log.d(TAG, "retryTimes:  " + retryTimes);
          try {
            Thread.sleep(2000);
          } catch (InterruptedException e) {
            Log.d(TAG, "InterruptedException:  " + e.toString());
            e.printStackTrace();
          }
          retryTimes++;
          return checkConnected();
        }
      }
      return false;
    }

  private int getNetworkId(String SSID) {
    List<WifiConfiguration>  confList = moWiFi.getConfiguredNetworks();
    if (confList != null && confList.size() > 0) {
      for (WifiConfiguration existingConfig : confList) {
        if (trimQuotes(existingConfig.SSID).equals(trimQuotes(SSID))) {
          // when pairing camera in android 5.1, phone has lost connection for a while.
          // then it reconnects to the router instead of camera.
          // solution: set camera priority to the highest. phone will reconnect the camera.
          int pri = 0;
          for (WifiConfiguration config : confList) {
            if (config.priority > pri) {
              pri = config.priority;
            }
          }
          int newPri = pri + 1;
          if (newPri >= 999999) {
            // We have reached a rare situation.
            Collections.sort(confList, new Comparator<WifiConfiguration>() {
              @Override
              public int compare(WifiConfiguration wc1, WifiConfiguration wc2) {
                return wc1.priority - wc2.priority;
              }
            });
            int size = confList.size();
            for (int ii = 0; ii < size; ii++) {
              WifiConfiguration config = confList.get(ii);
              config.priority = ii;
              moWiFi.updateNetwork(config);
            }
            moWiFi.saveConfiguration();
            newPri = size;
          }
          existingConfig.priority = newPri;
          moWiFi.updateNetwork(existingConfig);
          boolean es=moWiFi.saveConfiguration();
          Log.d(TAG, "saveConfiguration returned " + es );
          return existingConfig.networkId;
        }
      }
    }
    return -1;
  }

  private boolean connectWifiManager(int networkId,String ssid) {
    boolean enabled=false;
    int waiting_retries = 60;
    do {
      if ((moWiFi.getConnectionInfo() != null &&
        moWiFi.getConnectionInfo().getIpAddress() != 0) &&
        moWiFi.getDhcpInfo() != null && moWiFi.getDhcpInfo().ipAddress != 0) {
        //We're connected but don't have any IP yet
        Log.d(TAG, "IP: " + (moWiFi.getDhcpInfo().ipAddress & 0xFF) + "." + ((moWiFi.getDhcpInfo().ipAddress >> 8) & 0xFF) + "." +
          ((moWiFi.getDhcpInfo().ipAddress >> 16) & 0xFF) + "." + ((moWiFi.getDhcpInfo().ipAddress >> 24) & 0xFF));
        Log.d(TAG, "SV: " + (moWiFi.getDhcpInfo().serverAddress & 0xFF) + "." + ((moWiFi.getDhcpInfo().serverAddress >> 8) & 0xFF) + "." +
          ((moWiFi.getDhcpInfo().serverAddress >> 16) & 0xFF) + "." + ((moWiFi.getDhcpInfo().serverAddress >> 24) & 0xFF));


        String current_ssid = moWiFi.getConnectionInfo().getSSID();
        ConnectivityManager cm = (ConnectivityManager) moContext.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo info = cm.getActiveNetworkInfo();
        if (info != null && info.isConnected()) {
          current_ssid = info.getExtraInfo();
          Log.d(TAG, "WiFi SSID: " + current_ssid);
        }
        Log.d(TAG, "current_ssid: "+current_ssid);

        if (ssid != null &&
          (ssid.equals(convertToQuotedString(current_ssid)) ||
            ssid.equals(current_ssid))) {
          return true;
        } else {
          Log.d(TAG, "Connected to unexpected network -> try to enable expected network priority:");
          enabled = moWiFi.enableNetwork(networkId, true);

//          moWiFi.reconnect();
          Log.d(TAG, "enableNetwork: " + networkId + " : " + enabled);
        }
      }

      //Log.d(TAG, "connected but don't have any IP yet...");
      try {
        Thread.sleep(1000);
      } catch (InterruptedException e) {
        e.printStackTrace();
      }
    }
    while (waiting_retries-- > 0 );

    return enabled;
  }

  public static String convertToQuotedString(String string) {
    return "\"" + string + "\"";
  }

  private static String trimQuotes(String str) {
    if (!str.isEmpty()) {
      return str.replaceAll("^\"*", "").replaceAll("\"*$", "");
    }
    return str;
  }

  public static String ssidFormat(String str) {
    if (!str.isEmpty()) {
      return "\"" + str + "\"";
    }
    return str;
  }

    public static String sudoForResult(String... strings) {
        String res = "";
        DataOutputStream outputStream = null;
        InputStream response = null;
        try {
            Process su = Runtime.getRuntime().exec("su");
            outputStream = new DataOutputStream(su.getOutputStream());
            response = su.getInputStream();

            for (String s : strings) {
                outputStream.writeBytes(s + "\n");
                outputStream.flush();
            }

            outputStream.writeBytes("exit\n");
            outputStream.flush();
            try {
                su.waitFor();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            res = readFully(response);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            Closer.closeSilently(outputStream, response);
        }
        return res;
    }

    private static String readFully(InputStream is) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int length = 0;
        while ((length = is.read(buffer)) != -1) {
            baos.write(buffer, 0, length);
        }
        return baos.toString("UTF-8");
    }

    static class Closer {
        /// closeAll()
        public static void closeSilently(Object... xs) {
            /// Note: on Android API levels prior to 19 Socket does not implement Closeable
            for (Object x : xs) {
                if (x != null) {
                    try {
                        Log.d(Closer.class.toString(), "closing: " + x);
                        if (x instanceof Closeable) {
                            ((Closeable) x).close();
                        } else if (x instanceof Socket) {
                            ((Socket) x).close();
                        } else if (x instanceof DatagramSocket) {
                            ((DatagramSocket) x).close();
                        } else {
                            Log.d(Closer.class.toString(), "cannot close: " + x);
                            throw new RuntimeException("cannot close " + x);
                        }
                    } catch (Throwable e) {
                        Log.e(Closer.class.toString(), e.getMessage());
                    }
                }
            }
        }
    }
}

