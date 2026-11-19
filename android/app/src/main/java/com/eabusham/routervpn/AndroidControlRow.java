package com.eabusham.routervpn;

import android.content.Context;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;

/** Let the platform measure text at the user's scale before committing to a row. */
final class AndroidControlRow extends LinearLayout {
    AndroidControlRow(Context context) {
        super(context);
        setGravity(Gravity.CENTER_VERTICAL);
    }

    @Override protected void onMeasure(int widthSpec,int heightSpec) {
        int available=MeasureSpec.getSize(widthSpec)-getPaddingLeft()-getPaddingRight();
        int needed=0;
        for(int i=0;i<getChildCount();i++) {
            View child=getChildAt(i);
            if(child.getVisibility()==GONE)continue;
            LayoutParams p=(LayoutParams)child.getLayoutParams();
            child.measure(MeasureSpec.UNSPECIFIED,MeasureSpec.UNSPECIFIED);
            needed+=Math.max(child.getMeasuredWidth(),child.getMinimumWidth())+p.leftMargin+p.rightMargin;
        }
        boolean stack=MeasureSpec.getMode(widthSpec)!=MeasureSpec.UNSPECIFIED&&needed>available;
        int orientation=stack?VERTICAL:HORIZONTAL;
        if(getOrientation()!=orientation)setOrientation(orientation);
        for(int i=0;i<getChildCount();i++) {
            LayoutParams p=(LayoutParams)getChildAt(i).getLayoutParams();
            // Weighted horizontal fields need real width when they occupy their own line.
            if(p.weight>0 || p.width==LayoutParams.MATCH_PARENT) {
                p.width=stack?LayoutParams.MATCH_PARENT:0;
                p.weight=stack?0f:1f;
            }
        }
        super.onMeasure(widthSpec,heightSpec);
    }
}
