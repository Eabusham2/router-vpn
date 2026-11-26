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
import android.os.SystemClock;
import android.text.Layout;
import android.text.StaticLayout;
import android.text.TextPaint;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;
import android.view.accessibility.AccessibilityNodeInfo;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/** Offline native VPN globe. Callers provide only coordinates explicitly present in linked node data. */
final class RouterVpnNodeMapView extends View {
    interface OnMarkerClickListener { void onMarkerClick(Marker marker); }
    static final String ROLE_NORMAL="normal", ROLE_SELECTED="selected", ROLE_ENTRY="entry", ROLE_HOP="hop", ROLE_EXIT="exit", ROLE_EXTERNAL="external";
    private static final int LOCATION_PERMISSION_REQUEST=6403;
    private static final long MAX_LAST_LOCATION_AGE_MS=30*1000L;
    private static final float MAX_LOCATION_ACCURACY_METERS=10_000f;
    private static final int[] HOP_COLORS={0xff45c778,0xffc29cf2,0xfff2d15c,0xff57cfd6,0xfff25aad,0xff8a9cff};

    static final class Marker {
        final String id, name, role, measurement;
        final double latitude, longitude, latencyMs;
        final boolean selected, explicitCoordinates;
        Marker(String id,String name,double latitude,double longitude,boolean selected){this(id,name,latitude,longitude,selected?ROLE_SELECTED:ROLE_NORMAL,0);}
        Marker(String id,String name,double latitude,double longitude,String role){this(id,name,latitude,longitude,role,0);}
        Marker(String id,String name,double latitude,double longitude,String role,double latencyMs){this(id,name,latitude,longitude,role,latencyMs,false);}
        // Legacy Router profiles can use 0,0 as their unknown-location sentinel.
        // Typed external metadata retains absence separately from an explicit pair.
        Marker(String id,String name,double latitude,double longitude,String role,double latencyMs,boolean explicitCoordinates){
            this(id,name,latitude,longitude,role,latencyMs,explicitCoordinates,"");
        }
        Marker(String id,String name,double latitude,double longitude,String role,double latencyMs,boolean explicitCoordinates,String measurement){
            this.id=id;this.name=name;this.latitude=latitude;this.longitude=longitude;this.role=role==null?ROLE_NORMAL:role;
            this.selected=ROLE_SELECTED.equals(this.role);this.latencyMs=Double.isFinite(latencyMs)&&latencyMs>0?latencyMs:0;
            this.explicitCoordinates=explicitCoordinates;this.measurement=measurement;
        }
        String label(){
            String label=name==null||name.trim().isEmpty()?"Router VPN node":name.trim();
            if(label.length()>18)label=label.substring(0,17)+"…";
            if(latencyMs>0)label+="  "+String.format(Locale.US,"%.1f ms",latencyMs);
            if(latencyMs>0&&!measurement.isEmpty())label+=" "+measurement;
            return label;
        }
    }

    private final Paint background=paint(Color.rgb(9,17,31),1f);
    private final Paint oceanGlow=paint(Color.rgb(17,34,58),1f);
    private final Paint grid=paint(Color.rgb(39,58,83),1f);
    private final Paint axis=paint(Color.rgb(75,107,153),1.5f);
    private final Paint normalPin=paint(Color.rgb(72,199,214),1f);
    private final Paint selectedPin=paint(Color.rgb(145,108,255),1f);
    private final Paint entryPin=paint(Color.rgb(55,145,255),1f);
    private final Paint hopPin=paint(Color.rgb(55,207,183),1f);
    private final Paint exitPin=paint(Color.rgb(255,154,50),1f);
    private final Paint externalPin=paint(Color.rgb(242,91,172),1f);
    private final Paint userPin=paint(Color.rgb(78,214,132),1f);
    private final Paint locationButton=paint(Color.rgb(30,55,82),1f);
    private final Paint path=paint(Color.rgb(83,166,255),4f);
    private final Paint packet=paint(Color.WHITE,1f);
    private final Paint text=paint(Color.WHITE,1f);
    private final Paint secondary=paint(Color.rgb(160,180,208),1f);
    private List<Marker> markers=Collections.emptyList();
    private List<String> orderedPath=Collections.emptyList();
    private boolean orderedLive;
    private java.util.function.BooleanSupplier frameOwner;
    private OnMarkerClickListener markerClickListener;
    private final LocationManager locationManager;
    private final AndroidMapLand land;
    private LocationListener locationListener;
    private final Runnable locationExpiry = this::hideRealUserLocation;
    private Location userLocation;
    private boolean locationRequestPending;
    private boolean locationTouchStarted;
    private String locationState="LOCATE ME";
    private MapLayout cachedLayout;

    RouterVpnNodeMapView(Context context){this(context,null);}
    RouterVpnNodeMapView(Context context,AttributeSet attrs){
        super(context,attrs);
        text.setTextSize(sp(12));secondary.setTextSize(sp(10));
        setMinimumHeight((int)dp(260));
        setContentDescription("Router VPN globe. Only real coordinates from linked profiles are shown. Your location is hidden until you choose Locate me.");
        setFocusable(true);
        setClickable(true);
        locationManager=(LocationManager)context.getSystemService(Context.LOCATION_SERVICE);
        land=new AndroidMapLand(context.getAssets());
    }

    void setMarkers(List<Marker>value){markers=value==null?Collections.emptyList():new ArrayList<>(value);invalidate();}
    void setOrderedPath(List<String> value,boolean live,java.util.function.BooleanSupplier owner){orderedPath=value==null?Collections.emptyList():Collections.unmodifiableList(new ArrayList<>(value));orderedLive=live;frameOwner=owner;invalidate();}
    void setOnMarkerClickListener(OnMarkerClickListener listener){markerClickListener=listener;}

    @Override protected void onDraw(Canvas canvas){
        super.onDraw(canvas);MapLayout layout=mapLayout();RectF world=layout.world;
        canvas.drawRoundRect(layout.outer,dp(18),dp(18),background);
        drawTextBlock(canvas,layout.title,layout.outer.left,layout.outer.top+(layout.button.height()-(layout.title==null?0:layout.title.getHeight()))/2);
        drawLocationButton(canvas,layout);
        drawTextBlock(canvas,layout.legend,layout.outer.left,layout.outer.bottom-(layout.legend==null?0:layout.legend.getHeight()));
        if(world.width()<=0||world.height()<=0)return;
        canvas.save();canvas.clipRect(world);
        RectF glow=new RectF(world.left+dp(4),world.top+dp(4),world.right-dp(4),world.bottom-dp(4));canvas.drawOval(glow,oceanGlow);
        for(int lon=-120;lon<=120;lon+=60){float x=xFor(lon,world);canvas.drawLine(x,world.top,x,world.bottom,lon==0?axis:grid);}
        for(int lat=-60;lat<=60;lat+=30){float y=yFor(lat,world);canvas.drawLine(world.left,y,world.right,y,lat==0?axis:grid);}
        land.draw(canvas,world);
        text.setTextAlign(Paint.Align.LEFT);

        if(orderedLive && frameOwner!=null && !frameOwner.getAsBoolean())orderedLive=false;
        boolean animate=false;
        float phase=(SystemClock.elapsedRealtimeNanos()%1_800_000_000L)/1_800_000_000f;
        if(!orderedPath.isEmpty()) {
            for(int i=1;i<orderedPath.size();i++) {
                Marker a=null,b=null;
                for(Marker marker:markers){if(marker.id.equals(orderedPath.get(i-1)))a=marker;if(marker.id.equals(orderedPath.get(i)))b=marker;}
                // Missing coordinates break that segment; never invent a
                // shortcut that visually drops an intermediate selected node.
                if(a==null||b==null||!valid(a)||!valid(b))continue;
                path.setColor(routeColor(i,orderedPath.size()));
                drawRouteSegment(canvas,world,a,b,phase);
                animate=orderedLive;
            }
        }
        if(animate)postInvalidateDelayed(48);

        for(Marker marker:markers){
            if(!valid(marker))continue;float x=xFor(marker.longitude,world),y=yFor(marker.latitude,world);float r=dp(ROLE_SELECTED.equals(marker.role)||ROLE_ENTRY.equals(marker.role)||ROLE_HOP.equals(marker.role)||ROLE_EXIT.equals(marker.role)?8:6);
            int position=orderedPath.indexOf(marker.id);
            if(position>0&&ROLE_HOP.equals(marker.role))hopPin.setColor(routeColor(position,orderedPath.size()));
            if(marker.id.startsWith("external:")&&!ROLE_EXTERNAL.equals(marker.role))canvas.drawCircle(x,y,r+dp(2),externalPin);
            canvas.drawCircle(x,y,r,paintFor(marker.role));
            drawMarkerLabel(canvas,marker.label(),x,y,r,world);
        }
        if(validUserLocation()){
            float x=xFor(userLocation.getLongitude(),world),y=yFor(userLocation.getLatitude(),world);canvas.drawCircle(x,y,dp(12),halo(userPin.getColor()));canvas.drawCircle(x,y,dp(7),userPin);drawMarkerLabel(canvas,"YOU",x,y,dp(7),world);
        }
        if(markers.isEmpty()&&!validUserLocation())drawTextBlock(canvas,layout.empty,world.left+dp(6),world.centerY()-(layout.empty==null?0:layout.empty.getHeight())/2f);
        canvas.restore();
    }

    private int routeColor(int position,int count){
        if(position==0)return entryPin.getColor();
        if(position==count-1)return exitPin.getColor();
        return HOP_COLORS[(position-1)%HOP_COLORS.length];
    }

    private void drawRouteSegment(Canvas canvas,RectF world,Marker a,Marker b,float phase){
        float ax=xFor(a.longitude,world),ay=yFor(a.latitude,world);
        float bx=xFor(b.longitude,world),by=yFor(b.latitude,world);
        float width=world.width(),dx=bx-ax;
        if(width<=0)return;
        if(Math.abs(dx)>width/2){
            // Draw the short route across the date line, clipped at both map edges.
            boolean east=dx<0;
            dx+=east?width:-width;
            if(dx==0){
                canvas.drawLine(ax,ay,ax,by,path);
            }else{
                float edge=east?world.right:world.left;
                float crossY=ay+(by-ay)*(edge-ax)/dx;
                canvas.drawLine(ax,ay,edge,crossY,path);
                canvas.drawLine(east?world.left:world.right,crossY,bx,by,path);
            }
        }else{
            canvas.drawLine(ax,ay,bx,by,path);
        }
        if(orderedLive){
            float x=ax+dx*phase;
            if(x<world.left)x+=width;
            if(x>world.right)x-=width;
            canvas.drawCircle(x,ay+(by-ay)*phase,dp(4),packet);
        }
    }

    private void drawLocationButton(Canvas canvas,MapLayout layout){
        RectF button=layout.button;canvas.drawRoundRect(button,dp(12),dp(12),locationButton);
        drawTextBlock(canvas,layout.location,button.left+dp(10),button.centerY()-(layout.location==null?0:layout.location.getHeight())/2f);
    }

    private void drawMarkerLabel(Canvas canvas,String label,float x,float y,float radius,RectF world){
        float gap=radius+dp(4),right=world.right-x-gap,left=x-gap-world.left;
        boolean before=left>right;float width=Math.max(0,before?left:right);
        if(width<dp(24)||world.height()<text.getFontSpacing())return;
        CharSequence fitted=TextUtils.ellipsize(label,new TextPaint(text),width,TextUtils.TruncateAt.END);
        float start=before?x-gap-text.measureText(fitted.toString()):x+gap;
        float baseline=Math.max(world.top-text.ascent(),Math.min(y-dp(4),world.bottom-text.descent()));
        canvas.drawText(fitted.toString(),start,baseline,text);
    }

    @Override public boolean onTouchEvent(MotionEvent event){
        MapLayout layout=mapLayout();RectF world=layout.world;
        boolean onLocation=layout.button.contains(event.getX(),event.getY());
        switch(event.getActionMasked()){
            case MotionEvent.ACTION_DOWN:
                locationTouchStarted=onLocation;
                return true;
            case MotionEvent.ACTION_CANCEL:
            case MotionEvent.ACTION_POINTER_DOWN:
                locationTouchStarted=false;
                return true;
            case MotionEvent.ACTION_UP:
                boolean activate=locationTouchStarted && onLocation;
                boolean locationGesture=locationTouchStarted || onLocation;
                locationTouchStarted=false;
                if(activate)return performClick();
                if(locationGesture)return true;
                break;
            default: return true;
        }
        if(markerClickListener==null||markers.isEmpty()||!world.contains(event.getX(),event.getY()))return true;
        Marker best=null;float bestDistance=Float.MAX_VALUE;
        for(Marker marker:markers){if(!valid(marker))continue;float dx=xFor(marker.longitude,world)-event.getX(),dy=yFor(marker.latitude,world)-event.getY(),distance=(float)Math.hypot(dx,dy);if(distance<bestDistance){bestDistance=distance;best=marker;}}
        if(best!=null&&bestDistance<=dp(34))markerClickListener.onMarkerClick(best);
        return true;
    }

    private void enableRealUserLocation(){
        Activity activity=findActivity();
        if(activity==null||locationManager==null){locationState="LOCATION UNAVAILABLE";refreshLocationControl();return;}
        locationRequestPending=true;
        if(!hasLocationPermission()){
            locationState="ALLOW LOCATION";refreshLocationControl();
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
        else if(hasWindowFocus&&!hasLocationPermission())hideRealUserLocation();
    }

    @Override protected void onDetachedFromWindow(){
        hideRealUserLocation();
        super.onDetachedFromWindow();
    }

    private void requestFreshLocation(){
        hideRealUserLocation();
        if(locationManager==null||!hasLocationPermission())return;
        LocationListener listener=new LocationListener(){
            @Override public void onLocationChanged(Location location){
                if(locationListener==this)acceptRealLocation(location);
            }
            @Override public void onProviderDisabled(String provider){ }
            @Override public void onProviderEnabled(String provider){ }
            @Override public void onStatusChanged(String provider,int status,Bundle extras){ }
        };
        locationListener=listener;
        locationState="LOCATING…";
        postDelayed(locationExpiry,MAX_LAST_LOCATION_AGE_MS);
        boolean requested=false;
        try{
            for(String provider:locationManager.getProviders(true)){
                acceptRealLocation(locationManager.getLastKnownLocation(provider));
                if(LocationManager.GPS_PROVIDER.equals(provider)||LocationManager.NETWORK_PROVIDER.equals(provider)){
                    locationManager.requestSingleUpdate(provider,listener,Looper.getMainLooper());requested=true;
                }
            }
        }catch(SecurityException denied){hideRealUserLocation();return;}
        if(!requested&&!validUserLocation()){hideRealUserLocation();locationState="NO LOCATION FIX";}
        refreshLocationControl();
    }

    private void acceptRealLocation(Location location){
        if(locationListener==null||!hasLocationPermission()||!freshLocation(location))return;
        if(userLocation!=null&&location.getElapsedRealtimeNanos()<=userLocation.getElapsedRealtimeNanos())return;
        long ageMs=(SystemClock.elapsedRealtimeNanos()-location.getElapsedRealtimeNanos())/1_000_000L;
        removeCallbacks(locationExpiry);
        postDelayed(locationExpiry,Math.max(1,MAX_LAST_LOCATION_AGE_MS-ageMs));
        userLocation=new Location(location);locationState="HIDE ME";refreshLocationControl();
    }

    private void hideRealUserLocation(){
        LocationListener previous=locationListener;
        locationListener=null;
        locationRequestPending=false;
        removeCallbacks(locationExpiry);
        try{if(locationManager!=null&&previous!=null)locationManager.removeUpdates(previous);}catch(SecurityException ignored){}
        userLocation=null;locationState="LOCATE ME";refreshLocationControl();
    }

    private boolean hasLocationPermission(){return getContext().checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION)==PackageManager.PERMISSION_GRANTED||getContext().checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION)==PackageManager.PERMISSION_GRANTED;}
    private Activity findActivity(){Context c=getContext();while(c instanceof ContextWrapper){if(c instanceof Activity)return(Activity)c;c=((ContextWrapper)c).getBaseContext();}return c instanceof Activity?(Activity)c:null;}
    private boolean freshLocation(Location fix){
        if(fix==null||fix.getElapsedRealtimeNanos()<=0)return false;
        long age=SystemClock.elapsedRealtimeNanos()-fix.getElapsedRealtimeNanos();
        return age>=0&&age<MAX_LAST_LOCATION_AGE_MS*1_000_000L
                &&Double.isFinite(fix.getLatitude())&&Math.abs(fix.getLatitude())<=90
                &&Double.isFinite(fix.getLongitude())&&Math.abs(fix.getLongitude())<=180
                &&(!fix.hasAccuracy()||Float.isFinite(fix.getAccuracy())&&fix.getAccuracy()>=0&&fix.getAccuracy()<=MAX_LOCATION_ACCURACY_METERS);
    }
    private boolean validUserLocation(){return userLocation!=null&&hasLocationPermission()&&freshLocation(userLocation);}

    private void refreshLocationControl(){
        String status = validUserLocation() ? "Your location is visible." :
                "LOCATE ME".equals(locationState) ? "Your location is hidden." : locationState.toLowerCase(Locale.ROOT);
        setContentDescription("Router VPN globe. Only real coordinates from linked profiles are shown. " + status);
        invalidate();
    }

    @Override public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info){
        super.onInitializeAccessibilityNodeInfo(info);
        String label = validUserLocation() ? "Hide my location" : locationRequestPending || locationListener!=null ? "Cancel location request" : "Locate me";
        info.addAction(new AccessibilityNodeInfo.AccessibilityAction(AccessibilityNodeInfo.ACTION_CLICK,label));
    }

    @Override public boolean performClick(){
        super.performClick();
        if(locationRequestPending || locationListener!=null)hideRealUserLocation();
        else enableRealUserLocation();
        return true;
    }
    private static final class MapLayout {
        int width,height;
        String label;
        RectF outer,button,world;
        StaticLayout title,location,legend,empty;
    }

    private MapLayout mapLayout(){
        String label=validUserLocation()?"YOU • HIDE":locationState;
        if(cachedLayout!=null&&cachedLayout.width==getWidth()&&cachedLayout.height==getHeight()&&label.equals(cachedLayout.label))return cachedLayout;
        MapLayout value=new MapLayout();value.width=getWidth();value.height=getHeight();value.label=label;
        float padX=Math.min(dp(14),getWidth()/12f),padY=Math.min(dp(14),Math.max(0,(getHeight()-dp(48))/2f));
        value.outer=new RectF(padX,padY,Math.max(padX,getWidth()-padX),Math.max(padY,getHeight()-padY));
        float buttonWidth=Math.min(value.outer.width(),Math.max(dp(104),secondary.measureText(label)+dp(20)));
        value.location=textBlock(label,secondary,buttonWidth-dp(20),value.outer.height()-dp(12),2,Layout.Alignment.ALIGN_CENTER);
        float buttonHeight=Math.min(value.outer.height(),Math.max(dp(48),(value.location==null?0:value.location.getHeight())+dp(12)));
        value.button=new RectF(value.outer.right-buttonWidth,value.outer.top,value.outer.right,value.outer.top+buttonHeight);
        if(value.outer.height()<buttonHeight+dp(56)&&value.button.left-value.outer.left>dp(88)){
            // In a shallow landscape map, place the action beside the globe
            // instead of consuming its entire height with a text header.
            value.world=new RectF(value.outer.left,value.outer.top,value.button.left-dp(8),value.outer.bottom);
            value.empty=textBlock("No real node coordinates in linked profiles",text,value.world.width()-dp(12),value.world.height(),3,Layout.Alignment.ALIGN_CENTER);
            cachedLayout=value;return value;
        }
        value.title=textBlock("ROUTER VPN GLOBE",secondary,value.outer.width()-buttonWidth-dp(8),buttonHeight,2,Layout.Alignment.ALIGN_NORMAL);
        float worldTop=Math.min(value.outer.bottom,value.button.bottom+dp(8));
        // A short landscape viewport keeps the location action usable. Extra
        // explanatory text appears only when it leaves room for the real map;
        // its full meaning remains in the accessibility description.
        float legendBudget=value.outer.bottom-worldTop-Math.max(dp(60),text.getFontSpacing()*2)-dp(8);
        value.legend=textBlock("Only real coordinates • device location appears only after LOCATE ME",secondary,value.outer.width(),legendBudget,3,Layout.Alignment.ALIGN_NORMAL);
        float worldBottom=value.outer.bottom-(value.legend==null?0:value.legend.getHeight()+dp(8));
        value.world=new RectF(value.outer.left,worldTop,value.outer.right,Math.max(worldTop,worldBottom));
        value.empty=textBlock("No real node coordinates in linked profiles",text,value.world.width()-dp(12),value.world.height(),3,Layout.Alignment.ALIGN_CENTER);
        cachedLayout=value;return value;
    }

    private StaticLayout textBlock(String value,Paint paint,float width,float height,int maximumLines,Layout.Alignment alignment){
        if(width<dp(24)||height<=0)return null;
        TextPaint measured=new TextPaint(paint);measured.setTextAlign(Paint.Align.LEFT);
        int lines=Math.min(maximumLines,(int)(height/paint.getFontSpacing()));
        while(lines>0){
            StaticLayout block=StaticLayout.Builder.obtain(value,0,value.length(),measured,Math.max(1,(int)width))
                    .setAlignment(alignment).setIncludePad(false).setEllipsize(TextUtils.TruncateAt.END).setMaxLines(lines).build();
            if(block.getHeight()<=height)return block;
            lines--;
        }
        return null;
    }

    private void drawTextBlock(Canvas canvas,StaticLayout layout,float x,float y){
        if(layout==null)return;
        canvas.save();canvas.translate(x,y);layout.draw(canvas);canvas.restore();
    }
    private boolean valid(Marker m){return Double.isFinite(m.latitude)&&Double.isFinite(m.longitude)&&m.latitude>=-90&&m.latitude<=90&&m.longitude>=-180&&m.longitude<=180&&(m.explicitCoordinates||!(m.latitude==0&&m.longitude==0));}
    private float xFor(double lon,RectF world){return world.left+(float)((lon+180d)/360d)*world.width();}
    private float yFor(double lat,RectF world){return world.top+(float)((90d-lat)/180d)*world.height();}
    private Paint paintFor(String role){if(ROLE_ENTRY.equals(role))return entryPin;if(ROLE_HOP.equals(role))return hopPin;if(ROLE_EXIT.equals(role))return exitPin;if(ROLE_EXTERNAL.equals(role))return externalPin;if(ROLE_SELECTED.equals(role))return selectedPin;return normalPin;}
    private Paint halo(int color){Paint p=new Paint(Paint.ANTI_ALIAS_FLAG);p.setColor(Color.argb(58,Color.red(color),Color.green(color),Color.blue(color)));return p;}
    private Paint paint(int color,float widthDp){Paint p=new Paint(Paint.ANTI_ALIAS_FLAG);p.setColor(color);p.setStrokeWidth(dp(widthDp));p.setStrokeCap(Paint.Cap.ROUND);return p;}
    private float dp(float value){return value*getResources().getDisplayMetrics().density;}
    private float sp(float value){return value*getResources().getDisplayMetrics().scaledDensity;}
}
