"""Draw the shipping Android coastline with a recording Java2D graphics boundary."""
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'client/shared/map'
LAND = ROOT / 'android/app/src/main/java/com/eabusham/routervpn/AndroidMapLand.java'

SOURCES = {
    'android/content/res/AssetManager.java': '''package android.content.res;
import java.nio.file.*;import java.io.*;
public class AssetManager {
    private final Path root;
    public AssetManager(Path root){this.root=root;}
    public InputStream open(String name)throws IOException{return Files.newInputStream(root.resolve(name));}
}''',
    'android/util/Log.java': '''package android.util;
public class Log {public static int w(String tag,String message,Throwable cause){throw new AssertionError(message,cause);}}''',
    'android/graphics/Path.java': '''package android.graphics;
public class Path {
    public enum FillType {EVEN_ODD}
    final java.awt.geom.Path2D.Float delegate=new java.awt.geom.Path2D.Float();
    public void setFillType(FillType type){delegate.setWindingRule(java.awt.geom.Path2D.WIND_EVEN_ODD);}
    public void moveTo(float x,float y){delegate.moveTo(x,y);}
    public void lineTo(float x,float y){delegate.lineTo(x,y);}
    public void close(){delegate.closePath();}
}''',
    'android/graphics/Paint.java': '''package android.graphics;
public class Paint {
    public static final int ANTI_ALIAS_FLAG=1; public enum Style {STROKE}
    int color;Style style;public Paint(int flags){}
    public void setColor(int c){color=c;}public void setStyle(Style s){style=s;}public void setStrokeWidth(float w){}
}''',
    'android/graphics/RectF.java': '''package android.graphics;
public class RectF {
    public float left=20,top=10;public float width(){return 720;}public float height(){return 360;}
}''',
    'android/graphics/Canvas.java': '''package android.graphics;
import java.awt.*;import java.awt.geom.*;import java.awt.image.*;
public class Canvas {
    final BufferedImage image=new BufferedImage(760,380,BufferedImage.TYPE_INT_ARGB);
    final Graphics2D graphics=image.createGraphics();AffineTransform saved;
    public int save(){saved=graphics.getTransform();return 1;}
    public void translate(float x,float y){graphics.translate(x,y);}
    public void scale(float x,float y){graphics.scale(x,y);}
    public void drawPath(Path path,Paint paint){
        graphics.setColor(new Color(paint.color,true));
        if(paint.style==Paint.Style.STROKE){graphics.setStroke(new BasicStroke(0));graphics.draw(path.delegate);}
        else graphics.fill(path.delegate);
    }
    public void restoreToCount(int count){graphics.setTransform(saved);}
    public boolean land(int lon,int lat){return image.getRGB(20+(lon+180)*2,10+(90-lat)*2)!=0;}
    public boolean restored(){return graphics.getTransform().isIdentity();}
}''',
    'com/eabusham/routervpn/LandTest.java': '''package com.eabusham.routervpn;
import android.graphics.*;import android.content.res.AssetManager;import java.nio.file.Paths;
public class LandTest {
    public static void main(String[] args){
        AndroidMapLand map=new AndroidMapLand(new AssetManager(Paths.get(args[0])));
        Canvas canvas=new Canvas();map.draw(canvas,new RectF());
        for(int[] sample:new int[][]{{-99,40,1},{-55,-12,1},{135,-25,1},{25,0,1},{80,25,1},
                {-40,30,0},{-140,0,0},{80,-30,0},{51,42,0}}) {
            if(canvas.land(sample[0],sample[1])!=(sample[2]==1))
                throw new AssertionError("Wrong land/ocean at "+sample[0]+", "+sample[1]);
        }
        if(!canvas.restored())throw new AssertionError("Land transformed the node/route drawing context");
    }
}''',
}


def verify():
    jar = Path(os.environ.get('ANDROID_JSON_JAR', '/usr/share/java/com.android.json.jar'))
    with tempfile.TemporaryDirectory(prefix='routervpn-android-land-') as temporary:
        work = Path(temporary)
        for filename, contents in SOURCES.items():
            source = work / filename
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(contents)
        subprocess.run(['javac', '--release', '17', '-cp', str(jar), '-d', str(work),
                        str(LAND), *(str(work / path) for path in SOURCES)], check=True)
        subprocess.run(['java', '-Djava.awt.headless=true', '-cp', os.pathsep.join((str(work), str(jar))),
                        'com.eabusham.routervpn.LandTest', str(ASSETS)], check=True)
    spec = importlib.util.spec_from_file_location('android_delivery', ROOT / 'android/verify-delivery.py')
    delivery = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(delivery)
    for change in ('exact', 'missing notice', 'changed geography'):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            for asset in ASSETS.iterdir():
                if change == 'missing notice' and asset.suffix == '.txt':
                    continue
                data = asset.read_bytes()
                if change == 'changed geography' and asset.suffix == '.json':
                    data = b'!' + data[1:]
                archive.writestr('assets/' + asset.name, data)
        with zipfile.ZipFile(output) as archive:
            try:
                delivery.verify_map_assets(archive)
            except ValueError:
                if change == 'exact':
                    raise
            else:
                assert change == 'exact', f'delivery verified {change}'
    print('Android bundled map: five inland and four water samples, including an interior lake; original canvas restored')


if __name__ == '__main__':
    verify()
