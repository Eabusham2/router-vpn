package com.eabusham.routervpn;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Offline native coordinate view. Callers provide only coordinates explicitly present in linked node data. */
final class RouterVpnNodeMapView extends View {
    interface OnMarkerClickListener { void onMarkerClick(Marker marker); }
    static final String ROLE_NORMAL="normal", ROLE_SELECTED="selected", ROLE_ENTRY="entry", ROLE_EXIT="exit", ROLE_EXTERNAL="external";

    static final class Marker {
        final String id, name, role;
        final double latitude, longitude;
        final boolean selected;
        Marker(String id,String name,double latitude,double longitude,boolean selected){this(id,name,latitude,longitude,selected?ROLE_SELECTED:ROLE_NORMAL);}
        Marker(String id,String name,double latitude,double longitude,String role){this.id=id;this.name=name;this.latitude=latitude;this.longitude=longitude;this.role=role==null?ROLE_NORMAL:role;this.selected=ROLE_SELECTED.equals(this.role);}
    }

    private final Paint background=paint(Color.rgb(14,24,43),1f);
    private final Paint grid=paint(Color.rgb(45,61,87),1f);
    private final Paint axis=paint(Color.rgb(88,116,164),1.5f);
    private final Paint normalPin=paint(Color.rgb(72,199,214),1f);
    private final Paint selectedPin=paint(Color.rgb(145,108,255),1f);
    private final Paint entryPin=paint(Color.rgb(55,145,255),1f);
    private final Paint exitPin=paint(Color.rgb(255,154,50),1f);
    private final Paint externalPin=paint(Color.rgb(242,91,172),1f);
    private final Paint path=paint(Color.rgb(55,145,255),4f);
    private final Paint text=paint(Color.WHITE,1f);
    private List<Marker> markers=Collections.emptyList();
    private OnMarkerClickListener markerClickListener;

    RouterVpnNodeMapView(Context context){this(context,null);}
    RouterVpnNodeMapView(Context context,AttributeSet attrs){super(context,attrs);text.setTextSize(sp(12));setMinimumHeight((int)dp(260));setContentDescription("Interactive Router VPN node map using stored coordinates only");setClickable(true);}

    void setMarkers(List<Marker>value){markers=value==null?Collections.emptyList():new ArrayList<>(value);invalidate();}
    void setOnMarkerClickListener(OnMarkerClickListener listener){markerClickListener=listener;}

    @Override protected void onDraw(Canvas canvas){
        super.onDraw(canvas);RectF world=worldRect();canvas.drawRoundRect(world,dp(14),dp(14),background);
        for(int lon=-120;lon<=120;lon+=60){float x=xFor(lon,world);canvas.drawLine(x,world.top,x,world.bottom,lon==0?axis:grid);}
        for(int lat=-60;lat<=60;lat+=30){float y=yFor(lat,world);canvas.drawLine(world.left,y,world.right,y,lat==0?axis:grid);}
        if(markers.isEmpty()){text.setTextAlign(Paint.Align.CENTER);canvas.drawText("No real node coordinates in linked bundles",world.centerX(),world.centerY(),text);text.setTextAlign(Paint.Align.LEFT);return;}

        Marker entry=null,exit=null;
        for(Marker marker:markers){if(ROLE_ENTRY.equals(marker.role))entry=marker;else if(ROLE_EXIT.equals(marker.role))exit=marker;}
        if(entry!=null&&exit!=null&&valid(entry)&&valid(exit)){canvas.drawLine(xFor(entry.longitude,world),yFor(entry.latitude,world),xFor(exit.longitude,world),yFor(exit.latitude,world),path);}

        for(Marker marker:markers){
            if(!valid(marker))continue;float x=xFor(marker.longitude,world),y=yFor(marker.latitude,world);float r=dp(ROLE_SELECTED.equals(marker.role)||ROLE_ENTRY.equals(marker.role)||ROLE_EXIT.equals(marker.role)?8:6);canvas.drawCircle(x,y,r,paintFor(marker.role));
            String label=marker.name==null||marker.name.trim().isEmpty()?"Router VPN node":marker.name.trim();if(label.length()>22)label=label.substring(0,21)+"…";canvas.drawText(label,x+r+dp(4),y-dp(4),text);
        }
    }

    @Override public boolean onTouchEvent(MotionEvent event){
        if(event.getAction()!=MotionEvent.ACTION_UP)return true;
        if(markerClickListener==null||markers.isEmpty())return performClick();
        RectF world=worldRect();Marker best=null;float bestDistance=Float.MAX_VALUE;
        for(Marker marker:markers){if(!valid(marker))continue;float dx=xFor(marker.longitude,world)-event.getX(),dy=yFor(marker.latitude,world)-event.getY(),distance=(float)Math.hypot(dx,dy);if(distance<bestDistance){bestDistance=distance;best=marker;}}
        if(best!=null&&bestDistance<=dp(32)){markerClickListener.onMarkerClick(best);performClick();return true;}
        return performClick();
    }

    @Override public boolean performClick(){super.performClick();return true;}
    private RectF worldRect(){float pad=dp(14);return new RectF(pad,pad,getWidth()-pad,getHeight()-pad);}
    private boolean valid(Marker m){return Double.isFinite(m.latitude)&&Double.isFinite(m.longitude)&&m.latitude>=-90&&m.latitude<=90&&m.longitude>=-180&&m.longitude<=180&&!(m.latitude==0&&m.longitude==0);}
    private float xFor(double lon,RectF world){return world.left+(float)((lon+180d)/360d)*world.width();}
    private float yFor(double lat,RectF world){return world.top+(float)((90d-lat)/180d)*world.height();}
    private Paint paintFor(String role){if(ROLE_ENTRY.equals(role))return entryPin;if(ROLE_EXIT.equals(role))return exitPin;if(ROLE_EXTERNAL.equals(role))return externalPin;if(ROLE_SELECTED.equals(role))return selectedPin;return normalPin;}
    private Paint paint(int color,float widthDp){Paint p=new Paint(Paint.ANTI_ALIAS_FLAG);p.setColor(color);p.setStrokeWidth(dp(widthDp));p.setStrokeCap(Paint.Cap.ROUND);return p;}
    private float dp(float value){return value*getResources().getDisplayMetrics().density;}
    private float sp(float value){return value*getResources().getDisplayMetrics().scaledDensity;}
}
