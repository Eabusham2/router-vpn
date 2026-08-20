package com.eabusham.routervpn;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.pm.PackageManager;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RectF;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.Bundle;
import android.os.Looper;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/** Offline native VPN globe. Callers provide only coordinates explicitly present in linked node data. */
final class RouterVpnNodeMapView extends View {
    interface OnMarkerClickListener { void onMarkerClick(Marker marker); }
    static final String ROLE_NORMAL="normal", ROLE_SELECTED="selected", ROLE_ENTRY="entry", ROLE_EXIT="exit", ROLE_EXTERNAL="external";
    private static final int LOCATION_PERMISSION_REQUEST=6403;
    private static final long MAX_LAST_LOCATION_AGE_MS=5*60*1000L;

    static final class Marker {
        final String id, name, role;
        final double latitude, longitude, latencyMs;
        final boolean selected;
        Marker(String id,String name,double latitude,double longitude,boolean selected){this(id,name,latitude,longitude,selected?ROLE_SELECTED:ROLE_NORMAL,0);}
        Marker(String id,String name,double latitude,double longitude,String role){this(id,name,latitude,longitude,role,0);}
        Marker(String id,String name,double latitude,double longitude,String role,double latencyMs){this.id=id;this.name=name;this.latitude=latitude;this.longitude=longitude;this.role=role==null?ROLE_NORMAL:role;this.selected=ROLE_SELECTED.equals(this.role);this.latencyMs=Double.isFinite(latencyMs)&&latencyMs>0?latencyMs:0;}
    }

    private final Paint background=paint(Color.rgb(9,17,31),1f);
    private final Paint oceanGlow=paint(Color.rgb(17,34,58),1f);
    private final Paint grid=paint(Color.rgb(39,58,83),1f);
    private final Paint axis=paint(Color.rgb(75,107,153),1.5f);
    private final Paint normalPin=paint(Color.rgb(72,199,214),1f);
    private final Paint selectedPin=paint(Color.rgb(145,108,255),1f);
    private final Paint entryPin=paint(Color.rgb(55,145,255),1f);
    private final Paint exitPin=paint(Color.rgb(255,154,50),1f);
    private final Paint externalPin=paint(Color.rgb(242,91,172),1f);
    private final Paint userPin=paint(Color.rgb(78,214,132),1f);
    private final Paint locationButton=paint(Color.rgb(30,55,82),1f);
    private final Paint path=paint(Color.rgb(83,166,255),4f);
    private final Paint packet=paint(Color.WHITE,1f);
    private final Paint text=paint(Color.WHITE,1f);
    private final Paint secondary=paint(Color.rgb(160,180,208),1f);
    private List<Marker> markers=Collections.emptyList();
    private OnMarkerClickListener markerClickListener;
    private final LocationManager locationManager;
    private final LocationListener locationListener;
    private Location userLocation;
    private boolean locationRequestPending;
    private String locationState="LOCATE ME";

    RouterVpnNodeMapView(Context context){this(context,null);}
    RouterVpnNodeMapView(Context context,AttributeSet attrs){
        super(context,attrs);
        text.setTextSize(sp(12));secondary.setTextSize(sp(10));
        setMinimumHeight((int)dp(260));
        setContentDescription("Interactive Router VPN globe using stored node coordinates and measured latency only. Tap LOCATE ME to explicitly request a real device location marker.");
        setClickable(true);
        locationManager=(LocationManager)context.getSystemService(Context.LOCATION_SERVICE);
        locationListener=new LocationListener(){
            @Override public void onLocationChanged(Location location){acceptRealLocation(location);}
            @Override public void onProviderDisabled(String provider){ }
            @Override public void onProviderEnabled(String provider){ }
            @Override public void onStatusChanged(String provider,int status,Bundle extras){ }
        };
    }

    void setMarkers(List<Marker>value){markers=value==null?Collections.emptyList():new ArrayList<>(value);invalidate();}
    void setOnMarkerClickListener(OnMarkerClickListener listener){markerClickListener=listener;}

    @Override protected void onDraw(Canvas canvas){
        super.onDraw(canvas);RectF world=worldRect();canvas.drawRoundRect(world,dp(18),dp(18),background);
        RectF glow=new RectF(world.left+dp(4),world.top+dp(4),world.right-dp(4),world.bottom-dp(4));canvas.drawOval(glow,oceanGlow);
        for(int lon=-120;lon<=120;lon+=60){float x=xFor(lon,world);canvas.drawLine(x,world.top,x,world.bottom,lon==0?axis:grid);}
        for(int lat=-60;lat<=60;lat+=30){float y=yFor(lat,world);canvas.drawLine(world.left,y,world.right,y,lat==0?axis:grid);}
        text.setTextAlign(Paint.Align.LEFT);canvas.drawText("ROUTER VPN GLOBE",world.left+dp(12),world.top+dp(20),secondary);
        drawLocationButton(canvas,world);

        Marker entry=null,exit=null;
        for(Marker marker:markers){if(ROLE_ENTRY.equals(marker.role))entry=marker;else if(ROLE_EXIT.equals(marker.role))exit=marker;}
        if(entry!=null&&exit!=null&&valid(entry)&&valid(exit)){
            float ax=xFor(entry.longitude,world),ay=yFor(entry.latitude,world),bx=xFor(exit.longitude,world),by=yFor(exit.latitude,world);canvas.drawLine(ax,ay,bx,by,path);
            float phase=(System.currentTimeMillis()%1800L)/1800f;float px=ax+(bx-ax)*phase,py=ay+(by-ay)*phase;canvas.drawCircle(px,py,dp(4),packet);postInvalidateDelayed(48);
        }

        for(Marker marker:markers){
            if(!valid(marker))continue;float x=xFor(marker.longitude,world),y=yFor(marker.latitude,world);float r=dp(ROLE_SELECTED.equals(marker.role)||ROLE_ENTRY.equals(marker.role)||ROLE_EXIT.equals(marker.role)?8:6);canvas.drawCircle(x,y,r,paintFor(marker.role));
            String label=marker.name==null||marker.name.trim().isEmpty()?"Router VPN node":marker.name.trim();if(label.length()>18)label=label.substring(0,17)+"…";if(marker.latencyMs>0)label+="  "+String.format(Locale.US,"%.1f ms",marker.latencyMs);canvas.drawText(label,x+r+dp(4),y-dp(4),text);
        }
        if(validUserLocation()){
            float x=xFor(userLocation.getLongitude(),world),y=yFor(userLocation.getLatitude(),world);canvas.drawCircle(x,y,dp(12),halo(userPin.getColor()));canvas.drawCircle(x,y,dp(7),userPin);canvas.drawText("YOU",x+dp(11),y-dp(5),text);
        }
        if(markers.isEmpty()&&!validUserLocation()){text.setTextAlign(Paint.Align.CENTER);canvas.drawText("No real node coordinates in linked profiles",world.centerX(),world.centerY(),text);text.setTextAlign(Paint.Align.LEFT);}
        secondary.setTextAlign(Paint.Align.LEFT);canvas.drawText("Only real coordinates • device location appears only after LOCATE ME",world.left+dp(12),world.bottom-dp(10),secondary);
    }

    private void drawLocationButton(Canvas canvas,RectF world){
        RectF button=locationButtonRect(world);canvas.drawRoundRect(button,dp(12),dp(12),locationButton);secondary.setTextAlign(Paint.Align.CENTER);String label=validUserLocation()?"YOU • REFRESH":locationState;canvas.drawText(label,button.centerX(),button.centerY()+dp(3.5f),secondary);secondary.setTextAlign(Paint.Align.LEFT);
    }

    @Override public boolean onTouchEvent(MotionEvent event){
        if(event.getAction()!=MotionEvent.ACTION_UP)return true;
        RectF world=worldRect();
        if(locationButtonRect(world).contains(event.getX(),event.getY())){enableRealUserLocation();performClick();return true;}
        if(markerClickListener==null||markers.isEmpty())return performClick();
        Marker best=null;float bestDistance=Float.MAX_VALUE;
        for(Marker marker:markers){if(!valid(marker))continue;float dx=xFor(marker.longitude,world)-event.getX(),dy=yFor(marker.latitude,world)-event.getY(),distance=(float)Math.hypot(dx,dy);if(distance<bestDistance){bestDistance=distance;best=marker;}}
        if(best!=null&&bestDistance<=dp(34)){markerClickListener.onMarkerClick(best);performClick();return true;}
        return performClick();
    }

    private void enableRealUserLocation(){
        Activity activity=findActivity();
        if(activity==null||locationManager==null){locationState="LOCATION UNAVAILABLE";invalidate();return;}
        locationRequestPending=true;
        if(!hasLocationPermission()){
            locationState="ALLOW LOCATION";invalidate();
            activity.requestPermissions(new String[]{Manifest.permission.ACCESS_FINE_LOCATION,Manifest.permission.ACCESS_COARSE_LOCATION},LOCATION_PERMISSION_REQUEST);
            return;
        }
        requestFreshLocation();
    }

    @Override public void onWindowFocusChanged(boolean hasWindowFocus){
        super.onWindowFocusChanged(hasWindowFocus);
        // Android returns focus after the permission sheet. The request still
        // originates only from the user's LOCATE ME tap; no first-launch prompt.
        if(hasWindowFocus&&locationRequestPending&&hasLocationPermission())requestFreshLocation();
        else if(hasWindowFocus&&locationRequestPending&&!hasLocationPermission()){locationRequestPending=false;locationState="LOCATE ME";invalidate();}
    }

    private void requestFreshLocation(){
        if(locationManager==null||!hasLocationPermission()){locationRequestPending=false;locationState="LOCATE ME";invalidate();return;}
        locationRequestPending=false;locationState="LOCATING…";invalidate();
        boolean requested=false;
        try{
            long now=System.currentTimeMillis();
            for(String provider:locationManager.getProviders(true)){
                Location last=locationManager.getLastKnownLocation(provider);
                if(last!=null&&now-last.getTime()>=0&&now-last.getTime()<=MAX_LAST_LOCATION_AGE_MS)acceptRealLocation(last);
                if(LocationManager.GPS_PROVIDER.equals(provider)||LocationManager.NETWORK_PROVIDER.equals(provider)){
                    locationManager.requestSingleUpdate(provider,locationListener,Looper.getMainLooper());requested=true;
                }
            }
        }catch(SecurityException ignored){requested=false;}
        if(!requested&&!validUserLocation()){locationState="NO LOCATION FIX";invalidate();}
    }

    private void acceptRealLocation(Location location){
        if(location==null||!Double.isFinite(location.getLatitude())||!Double.isFinite(location.getLongitude())||location.getLatitude()<-90||location.getLatitude()>90||location.getLongitude()<-180||location.getLongitude()>180)return;
        userLocation=new Location(location);locationState="LOCATE ME";invalidate();
    }

    private boolean hasLocationPermission(){return getContext().checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION)==PackageManager.PERMISSION_GRANTED||getContext().checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION)==PackageManager.PERMISSION_GRANTED;}
    private Activity findActivity(){Context c=getContext();while(c instanceof ContextWrapper){if(c instanceof Activity)return(Activity)c;c=((ContextWrapper)c).getBaseContext();}return c instanceof Activity?(Activity)c:null;}
    private boolean validUserLocation(){return userLocation!=null&&Double.isFinite(userLocation.getLatitude())&&Double.isFinite(userLocation.getLongitude())&&userLocation.getLatitude()>=-90&&userLocation.getLatitude()<=90&&userLocation.getLongitude()>=-180&&userLocation.getLongitude()<=180;}
    private RectF locationButtonRect(RectF world){float w=dp(104),h=dp(28);return new RectF(world.right-w-dp(10),world.top+dp(8),world.right-dp(10),world.top+dp(8)+h);}

    @Override public boolean performClick(){super.performClick();return true;}
    private RectF worldRect(){float pad=dp(14);return new RectF(pad,pad,getWidth()-pad,getHeight()-pad);}
    private boolean valid(Marker m){return Double.isFinite(m.latitude)&&Double.isFinite(m.longitude)&&m.latitude>=-90&&m.latitude<=90&&m.longitude>=-180&&m.longitude<=180&&!(m.latitude==0&&m.longitude==0);}
    private float xFor(double lon,RectF world){return world.left+(float)((lon+180d)/360d)*world.width();}
    private float yFor(double lat,RectF world){return world.top+(float)((90d-lat)/180d)*world.height();}
    private Paint paintFor(String role){if(ROLE_ENTRY.equals(role))return entryPin;if(ROLE_EXIT.equals(role))return exitPin;if(ROLE_EXTERNAL.equals(role))return externalPin;if(ROLE_SELECTED.equals(role))return selectedPin;return normalPin;}
    private Paint halo(int color){Paint p=new Paint(Paint.ANTI_ALIAS_FLAG);p.setColor(Color.argb(58,Color.red(color),Color.green(color),Color.blue(color)));return p;}
    private Paint paint(int color,float widthDp){Paint p=new Paint(Paint.ANTI_ALIAS_FLAG);p.setColor(color);p.setStrokeWidth(dp(widthDp));p.setStrokeCap(Paint.Cap.ROUND);return p;}
    private float dp(float value){return value*getResources().getDisplayMetrics().density;}
    private float sp(float value){return value*getResources().getDisplayMetrics().scaledDensity;}
}
