"""GitX app icon — classic Mac OS X Leopard "photo-illustrative" instrument render.

Run headless:
    blender -b -P assets/icon-src/gitx_icon.py -- --res 1024 --samples 256 --out assets/icon.png

Craft principles (after Apple's Mac OS X Human Interface Guidelines & Leopard icon craft):
  * Single physical precision instrument standing on a desk directly in front of
    the viewer: subtle backward lean + slightly elevated telephoto camera for
    gentle diminishing perspective while keeping the circular emblem heroic.
  * Unified overhead studio key light with high-contrast studio reflection cards,
    negative-fill dark strips, and a soft desk bounce below so brushed aluminum
    and mirror chrome feel genuinely weighty on both light and dark backdrops.
  * Multi-layered real materials & 1024px micro-detail:
      - Concentric lathe-brushed satin aluminum bezel + fluted outer drum
      - Crisp polished chrome outer & inner step-chamfers
      - 4 countersunk machined micro-screws with dark slotted heads
      - Sloped dark-titanium chapter ring with 60 raised silver 3D index ticks
      - Deep radiant sunburst sapphire enamel dial with etched orbital hairlines
      - Mirror-chrome Git branching rails with recessed channels & mounting collars
      - Deep, jewel-saturated Aqua "gel" glass commit orbs seated in concave
        chrome reflector cups (Cyan root, Emerald main HEAD, Rust-Vermilion branch)
      - Single-surface optical watch crystal catching a silky curved Aqua sheen
  * Grounded by an authentic overhead-lit contact & drop shadow on alpha.
"""
import bpy
import bmesh
import math
import sys
from mathutils import Vector, Matrix

argv = sys.argv[sys.argv.index("--") + 1:] if "--" in sys.argv else []

def arg(name, default):
    if name in argv:
        return type(default)(argv[argv.index(name) + 1])
    return default

RES = arg("--res", 1024)
SAMPLES = arg("--samples", 256)
OUT = arg("--out", "assets/icon.png")
SAVE_BLEND = arg("--blend", "")
TILT_DEG = arg("--tilt", 75.0)       # 15° gentle desk lean
CAM_ELEV = arg("--elev", 10.5)
CAM_DIST = arg("--dist", 6.85)
CRYSTAL_STRENGTH = arg("--crystal", 0.72)

# ---------------------------------------------------------------- scene reset
bpy.ops.wm.read_factory_settings(use_empty=True)
scene = bpy.context.scene

rig = bpy.data.objects.new("Rig", None)
scene.collection.objects.link(rig)
rig.rotation_euler = (math.radians(TILT_DEG), 0.0, 0.0)

def link(obj, parent=rig):
    scene.collection.objects.link(obj)
    if parent is not None:
        obj.parent = parent
    return obj

# ---------------------------------------------------------------- materials
def principled(mat):
    return next(n for n in mat.node_tree.nodes if n.type == "BSDF_PRINCIPLED")

def output_node(mat):
    return next(n for n in mat.node_tree.nodes if n.type == "OUTPUT_MATERIAL")

def ensure_nodes(datablock):
    if getattr(datablock, "node_tree", None) is None:
        datablock.use_nodes = True
    return datablock.node_tree

def new_mat(name, color, metallic=0.0, rough=0.5):
    m = bpy.data.materials.new(name)
    ensure_nodes(m)
    p = principled(m)
    p.inputs["Base Color"].default_value = (*color, 1.0)
    p.inputs["Metallic"].default_value = metallic
    p.inputs["Roughness"].default_value = rough
    return m

def mat_brushed_alu():
    """Concentric lathe-brushed satin aluminum bezel (classic Apple hardware)."""
    m = new_mat("BrushedAluminum", (0.86, 0.88, 0.91), 1.0, 0.22)
    nt, p = m.node_tree, principled(m)
    p.inputs["Anisotropic"].default_value = 0.86
    p.inputs["Anisotropic Rotation"].default_value = 0.0
    tan = nt.nodes.new("ShaderNodeTangent")
    tan.direction_type = "RADIAL"
    tan.axis = "Z"
    nt.links.new(tan.outputs["Tangent"], p.inputs["Tangent"])

    tc = nt.nodes.new("ShaderNodeTexCoord")
    sep = nt.nodes.new("ShaderNodeSeparateXYZ")
    nt.links.new(tc.outputs["Object"], sep.inputs[0])
    comb = nt.nodes.new("ShaderNodeCombineXYZ")
    nt.links.new(sep.outputs["X"], comb.inputs["X"])
    nt.links.new(sep.outputs["Y"], comb.inputs["Y"])
    r = nt.nodes.new("ShaderNodeVectorMath")
    r.operation = "LENGTH"
    nt.links.new(comb.outputs[0], r.inputs[0])

    noise = nt.nodes.new("ShaderNodeTexNoise")
    noise.noise_dimensions = "1D"
    noise.inputs["Scale"].default_value = 680.0
    noise.inputs["Detail"].default_value = 10.0
    noise.inputs["Roughness"].default_value = 0.62
    nt.links.new(r.outputs["Value"], noise.inputs["W"])

    bump = nt.nodes.new("ShaderNodeBump")
    bump.inputs["Strength"].default_value = 0.16
    bump.inputs["Distance"].default_value = 0.0020
    nt.links.new(noise.outputs["Fac"], bump.inputs["Height"])
    nt.links.new(bump.outputs["Normal"], p.inputs["Normal"])

    ramp = nt.nodes.new("ShaderNodeMapRange")
    ramp.inputs["To Min"].default_value = 0.16
    ramp.inputs["To Max"].default_value = 0.28
    nt.links.new(noise.outputs["Fac"], ramp.inputs["Value"])
    nt.links.new(ramp.outputs["Result"], p.inputs["Roughness"])
    return m

def mat_chapter_titanium():
    """Dark satin-anodized titanium for the recessed chapter ring so bright
    silver tick marks pop with razor-sharp chronograph precision."""
    m = new_mat("ChapterTitanium", (0.20, 0.24, 0.31), 1.0, 0.30)
    nt, p = m.node_tree, principled(m)
    p.inputs["Anisotropic"].default_value = 0.70
    tan = nt.nodes.new("ShaderNodeTangent")
    tan.direction_type = "RADIAL"
    tan.axis = "Z"
    nt.links.new(tan.outputs["Tangent"], p.inputs["Tangent"])
    return m

def mat_fluted_rim():
    """Machined vertical fluting/knurling around the outer drum wall."""
    m = new_mat("FlutedRim", (0.78, 0.80, 0.84), 1.0, 0.14)
    nt, p = m.node_tree, principled(m)
    tc = nt.nodes.new("ShaderNodeTexCoord")
    sep = nt.nodes.new("ShaderNodeSeparateXYZ")
    nt.links.new(tc.outputs["Object"], sep.inputs[0])
    at = nt.nodes.new("ShaderNodeMath")
    at.operation = "ARCTAN2"
    nt.links.new(sep.outputs["Y"], at.inputs[0])
    nt.links.new(sep.outputs["X"], at.inputs[1])
    mul = nt.nodes.new("ShaderNodeMath")
    mul.operation = "MULTIPLY"
    mul.inputs[1].default_value = 120.0
    nt.links.new(at.outputs[0], mul.inputs[0])
    sn = nt.nodes.new("ShaderNodeMath")
    sn.operation = "SINE"
    nt.links.new(mul.outputs[0], sn.inputs[0])
    bump = nt.nodes.new("ShaderNodeBump")
    bump.inputs["Strength"].default_value = 0.50
    bump.inputs["Distance"].default_value = 0.005
    nt.links.new(sn.outputs[0], bump.inputs["Height"])
    nt.links.new(bump.outputs["Normal"], p.inputs["Normal"])
    return m

def mat_chrome():
    return new_mat("Chrome", (0.96, 0.97, 1.00), 1.0, 0.022)

def mat_satin_collar():
    return new_mat("SatinCollar", (0.72, 0.75, 0.80), 1.0, 0.18)

def mat_dark_gunmetal():
    return new_mat("DarkGunmetal", (0.015, 0.025, 0.055), 0.85, 0.28)

def mat_tick_silver():
    m = new_mat("TickSilver", (0.95, 0.97, 1.00), 0.55, 0.12)
    p = principled(m)
    p.inputs["Emission Color"].default_value = (0.85, 0.92, 1.0, 1.0)
    p.inputs["Emission Strength"].default_value = 0.14
    return m

def mat_dial_enamel():
    """Deep, lustrous Mac OS X Safari-inspired sunburst sapphire enamel dial.

    Electric royal-cerulean glow in the heart deepening smoothly to velvety
    midnight indigo at the outer rim, under a glossy piano-lacquer coat.
    """
    m = new_mat("DialEnamel", (0.01, 0.10, 0.36), 0.18, 0.22)
    nt, p = m.node_tree, principled(m)
    p.inputs["Coat Weight"].default_value = 1.0
    p.inputs["Coat Roughness"].default_value = 0.03
    p.inputs["Coat IOR"].default_value = 1.54
    p.inputs["Anisotropic"].default_value = 0.55

    tan = nt.nodes.new("ShaderNodeTangent")
    tan.direction_type = "RADIAL"
    tan.axis = "Z"
    nt.links.new(tan.outputs["Tangent"], p.inputs["Tangent"])

    tc = nt.nodes.new("ShaderNodeTexCoord")
    sep = nt.nodes.new("ShaderNodeSeparateXYZ")
    nt.links.new(tc.outputs["Object"], sep.inputs[0])

    comb = nt.nodes.new("ShaderNodeCombineXYZ")
    nt.links.new(sep.outputs["X"], comb.inputs["X"])
    nt.links.new(sep.outputs["Y"], comb.inputs["Y"])
    r_len = nt.nodes.new("ShaderNodeVectorMath")
    r_len.operation = "LENGTH"
    nt.links.new(comb.outputs[0], r_len.inputs[0])

    r_norm = nt.nodes.new("ShaderNodeMapRange")
    r_norm.inputs["From Min"].default_value = 0.0
    r_norm.inputs["From Max"].default_value = 0.72
    nt.links.new(r_len.outputs["Value"], r_norm.inputs["Value"])

    # High-contrast royal sapphire radial vignette
    cr = nt.nodes.new("ShaderNodeValToRGB")
    cr.color_ramp.interpolation = "B_SPLINE"
    e0 = cr.color_ramp.elements[0]
    e0.position = 0.0
    e0.color = (0.020, 0.24, 0.74, 1.0)
    e1 = cr.color_ramp.elements[1]
    e1.position = 1.0
    e1.color = (0.002, 0.008, 0.038, 1.0)
    em = cr.color_ramp.elements.new(0.52)
    em.color = (0.008, 0.085, 0.34, 1.0)
    nt.links.new(r_norm.outputs["Result"], cr.inputs["Fac"])
    nt.links.new(cr.outputs["Color"], p.inputs["Base Color"])

    # Gentle central sapphire backlight glow
    p.inputs["Emission Color"].default_value = (0.015, 0.18, 0.68, 1.0)
    em_fall = nt.nodes.new("ShaderNodeMapRange")
    em_fall.inputs["From Min"].default_value = 0.0
    em_fall.inputs["From Max"].default_value = 0.78
    em_fall.inputs["To Min"].default_value = 0.26
    em_fall.inputs["To Max"].default_value = 0.0
    nt.links.new(r_norm.outputs["Result"], em_fall.inputs["Value"])
    nt.links.new(em_fall.outputs["Result"], p.inputs["Emission Strength"])

    # Fine concentric guilloché micro-rings + sunburst micro-grain
    ang = nt.nodes.new("ShaderNodeMath")
    ang.operation = "ARCTAN2"
    nt.links.new(sep.outputs["Y"], ang.inputs[0])
    nt.links.new(sep.outputs["X"], ang.inputs[1])

    sun_noise = nt.nodes.new("ShaderNodeTexNoise")
    sun_noise.noise_dimensions = "1D"
    sun_noise.inputs["Scale"].default_value = 260.0
    sun_noise.inputs["Detail"].default_value = 6.0
    nt.links.new(ang.outputs[0], sun_noise.inputs["W"])

    ring_mul = nt.nodes.new("ShaderNodeMath")
    ring_mul.operation = "MULTIPLY"
    ring_mul.inputs[1].default_value = 290.0
    nt.links.new(r_len.outputs["Value"], ring_mul.inputs[0])
    ring_sin = nt.nodes.new("ShaderNodeMath")
    ring_sin.operation = "SINE"
    nt.links.new(ring_mul.outputs[0], ring_sin.inputs[0])

    mix_h = nt.nodes.new("ShaderNodeMath")
    mix_h.operation = "MULTIPLY_ADD"
    mix_h.inputs[1].default_value = 0.25
    nt.links.new(ring_sin.outputs[0], mix_h.inputs[0])
    nt.links.new(sun_noise.outputs["Fac"], mix_h.inputs[2])

    bump = nt.nodes.new("ShaderNodeBump")
    bump.inputs["Strength"].default_value = 0.09
    bump.inputs["Distance"].default_value = 0.0012
    nt.links.new(mix_h.outputs[0], bump.inputs["Height"])
    nt.links.new(bump.outputs["Normal"], p.inputs["Normal"])
    return m

def mat_dial_ring():
    m = new_mat("DialRing", (0.28, 0.58, 0.96), 0.70, 0.16)
    p = principled(m)
    p.inputs["Emission Color"].default_value = (0.18, 0.48, 0.95, 1.0)
    p.inputs["Emission Strength"].default_value = 0.20
    return m

def mat_reflector_dish(name, tint):
    """Colored metallic concave mirror dish beneath each gel jewel so the
    translucent gem glows with pure, unmuddied internal reflection."""
    m = new_mat(name, tint, 0.92, 0.14)
    p = principled(m)
    p.inputs["Emission Color"].default_value = (*tint, 1.0)
    p.inputs["Emission Strength"].default_value = 0.28
    return m

def mat_gel(name, base_col, core_col, glow_col, glow_gain=1.35, density=11.0):
    """Authentic Mac OS X Aqua 'lickable' gel-glass jewel.

    Rich, deeply saturated upper dome (zero pastel washout!) transitioning into
    a tight, jewel-bright caustic glow pooled at the bottom crescent, topped by
    a razor-sharp clearcoat specular glint.
    """
    m = bpy.data.materials.new(name)
    nt = ensure_nodes(m)
    p = principled(m)
    p.inputs["Base Color"].default_value = (*base_col, 1.0)
    p.inputs["Transmission Weight"].default_value = 0.94
    p.inputs["Roughness"].default_value = 0.008
    p.inputs["IOR"].default_value = 1.52
    p.inputs["Coat Weight"].default_value = 1.0
    p.inputs["Coat Roughness"].default_value = 0.004
    p.inputs["Coat IOR"].default_value = 1.62

    # Tight bottom-crescent caustic glow (classic Aqua internal light focus)
    tc = nt.nodes.new("ShaderNodeTexCoord")
    sep = nt.nodes.new("ShaderNodeSeparateXYZ")
    nt.links.new(tc.outputs["Object"], sep.inputs[0])

    # Local -Y points down; confine glow strictly to the lower hemisphere
    mr = nt.nodes.new("ShaderNodeMapRange")
    mr.inputs["From Min"].default_value = -0.01
    mr.inputs["From Max"].default_value = -0.145
    nt.links.new(sep.outputs["Y"], mr.inputs["Value"])

    pw = nt.nodes.new("ShaderNodeMath")
    pw.operation = "POWER"
    pw.inputs[1].default_value = 2.2
    nt.links.new(mr.outputs["Result"], pw.inputs[0])

    # Keep outer edge dark-rimmed & jewel-like via Facing falloff
    lw = nt.nodes.new("ShaderNodeLayerWeight")
    lw.inputs["Blend"].default_value = 0.45
    inv = nt.nodes.new("ShaderNodeMath")
    inv.operation = "SUBTRACT"
    inv.inputs[0].default_value = 1.0
    nt.links.new(lw.outputs["Facing"], inv.inputs[1])

    mul = nt.nodes.new("ShaderNodeMath")
    mul.operation = "MULTIPLY"
    nt.links.new(pw.outputs[0], mul.inputs[0])
    nt.links.new(inv.outputs[0], mul.inputs[1])

    gain = nt.nodes.new("ShaderNodeMath")
    gain.operation = "MULTIPLY"
    gain.inputs[1].default_value = glow_gain
    nt.links.new(mul.outputs[0], gain.inputs[0])

    p.inputs["Emission Color"].default_value = (*glow_col, 1.0)
    nt.links.new(gain.outputs[0], p.inputs["Emission Strength"])

    vol = nt.nodes.new("ShaderNodeVolumeAbsorption")
    vol.inputs["Color"].default_value = (*core_col, 1.0)
    vol.inputs["Density"].default_value = density
    nt.links.new(vol.outputs[0], output_node(m).inputs["Volume"])
    return m

def mat_watch_crystal():
    """Optical watch crystal: transparent to shadows & interior light, with a
    delicate, curved Fresnel studio sheen across the upper dome."""
    m = bpy.data.materials.new("WatchCrystal")
    nt = ensure_nodes(m)
    for n in list(nt.nodes):
        if n.type != "OUTPUT_MATERIAL":
            nt.nodes.remove(n)
    out = output_node(m)

    transp = nt.nodes.new("ShaderNodeBsdfTransparent")
    transp.inputs["Color"].default_value = (1.0, 1.0, 1.0, 1.0)

    glossy = nt.nodes.new("ShaderNodeBsdfGlossy")
    glossy.inputs["Color"].default_value = (0.98, 0.99, 1.0, 1.0)
    glossy.inputs["Roughness"].default_value = 0.008

    fresnel = nt.nodes.new("ShaderNodeFresnel")
    fresnel.inputs["IOR"].default_value = 1.48

    # Slightly lift base reflectivity + Fresnel so the curved upper sheen is unmistakable
    lift = nt.nodes.new("ShaderNodeMapRange")
    lift.inputs["From Min"].default_value = 0.0
    lift.inputs["From Max"].default_value = 1.0
    lift.inputs["To Min"].default_value = 0.045 * CRYSTAL_STRENGTH
    lift.inputs["To Max"].default_value = 0.85 * CRYSTAL_STRENGTH
    nt.links.new(fresnel.outputs[0], lift.inputs["Value"])

    mix_glass = nt.nodes.new("ShaderNodeMixShader")
    nt.links.new(lift.outputs["Result"], mix_glass.inputs["Fac"])
    nt.links.new(transp.outputs[0], mix_glass.inputs[1])
    nt.links.new(glossy.outputs[0], mix_glass.inputs[2])

    lp = nt.nodes.new("ShaderNodeLightPath")
    mix_shad = nt.nodes.new("ShaderNodeMixShader")
    nt.links.new(lp.outputs["Is Shadow Ray"], mix_shad.inputs["Fac"])
    nt.links.new(mix_glass.outputs[0], mix_shad.inputs[1])
    nt.links.new(transp.outputs[0], mix_shad.inputs[2])

    nt.links.new(mix_shad.outputs[0], out.inputs["Surface"])
    return m

ALU       = mat_brushed_alu()
CHAPTER   = mat_chapter_titanium()
FLUTED    = mat_fluted_rim()
CHROME    = mat_chrome()
COLLAR    = mat_satin_collar()
GUNMETAL  = mat_dark_gunmetal()
TICK_MAT  = mat_tick_silver()
DIAL      = mat_dial_enamel()
DIAL_RING = mat_dial_ring()
CRYSTAL   = mat_watch_crystal()

# Deep, rich, ultra-saturated Aqua jewel tones (tuned for AgX so they stay lush!)
GEL_CYAN   = mat_gel("GelCyan",   (0.02, 0.48, 1.00), (0.005, 0.24, 0.90), (0.08, 0.78, 1.00), glow_gain=1.65, density=10.5)
GEL_GREEN  = mat_gel("GelGreen",  (0.02, 0.82, 0.16), (0.005, 0.52, 0.06), (0.14, 1.00, 0.26), glow_gain=1.45, density=11.0)
GEL_ORANGE = mat_gel("GelOrange", (1.00, 0.14, 0.005),(0.92,  0.08, 0.002),(1.00, 0.32, 0.01), glow_gain=1.85, density=12.5)

DISH_CYAN   = mat_reflector_dish("DishCyan",   (0.02, 0.36, 0.88))
DISH_GREEN  = mat_reflector_dish("DishGreen",  (0.02, 0.62, 0.14))
DISH_ORANGE = mat_reflector_dish("DishOrange", (0.90, 0.16, 0.01))

# ---------------------------------------------------------------- geometry helpers
def fillet(points, radius, segs=6):
    out = [points[0][:3]]
    for i in range(1, len(points) - 1):
        p0, p1, p2 = (Vector(points[j][:2]) for j in (i - 1, i, i + 1))
        rad = points[i][3] if len(points[i]) > 3 else radius
        a, b = (p0 - p1), (p2 - p1)
        la, lb = a.length, b.length
        a.normalize()
        b.normalize()
        d = min(rad, la * 0.45, lb * 0.45)
        s, e = p1 + a * d, p1 + b * d
        for k in range(segs + 1):
            t = k / segs
            q = (1 - t) ** 2 * s + 2 * (1 - t) * t * p1 + t * t * e
            out.append((q.x, q.y, points[i][2]))
    out.append(points[-1][:3])
    return out

def lathe(name, profile, mats, steps=256):
    me = bpy.data.meshes.new(name)
    bm = bmesh.new()
    rings = []
    for k in range(steps):
        ang = 2 * math.pi * k / steps
        c, s = math.cos(ang), math.sin(ang)
        rings.append([bm.verts.new((r * c, r * s, z)) for r, z, _ in profile])
    for k in range(steps):
        a, b = rings[k], rings[(k + 1) % steps]
        for i in range(len(profile) - 1):
            if profile[i][0] < 1e-6 and profile[i + 1][0] < 1e-6:
                continue
            try:
                f = bm.faces.new([a[i], b[i], b[i + 1], a[i + 1]])
            except ValueError:
                continue
            f.material_index = profile[i + 1][2]
            f.smooth = True
    bmesh.ops.remove_doubles(bm, verts=bm.verts, dist=1e-6)
    bmesh.ops.recalc_face_normals(bm, faces=bm.faces)
    bm.to_mesh(me)
    bm.free()
    for m in mats:
        me.materials.append(m)
    return link(bpy.data.objects.new(name, me))

def add_torus(name, major_r, minor_r, loc, mat, maj_seg=128, min_seg=28):
    me = bpy.data.meshes.new(name)
    bm = bmesh.new()
    rings = []
    for i in range(maj_seg):
        th = 2 * math.pi * i / maj_seg
        ct, st = math.cos(th), math.sin(th)
        ring = []
        for j in range(min_seg):
            ph = 2 * math.pi * j / min_seg
            r = major_r + minor_r * math.cos(ph)
            z = minor_r * math.sin(ph)
            ring.append(bm.verts.new((r * ct, r * st, z)))
        rings.append(ring)
    for i in range(maj_seg):
        r0, r1 = rings[i], rings[(i + 1) % maj_seg]
        for j in range(min_seg):
            f = bm.faces.new([r0[j], r1[j], r1[(j + 1) % min_seg], r0[(j + 1) % min_seg]])
            f.smooth = True
    bmesh.ops.recalc_face_normals(bm, faces=bm.faces)
    bm.to_mesh(me)
    bm.free()
    ob = link(bpy.data.objects.new(name, me))
    ob.location = loc
    ob.data.materials.append(mat)
    return ob

# ---------------------------------------------------------------- machined housing
# Materials: 0=ALU, 1=CHROME, 2=FLUTED, 3=CHAPTER
FACE_R = 0.722
WELL = -0.078

body_profile = fillet([
    (0.000, -0.31, 0),
    (0.945, -0.31, 0),
    (0.990, -0.27, 1, 0.025),    # bottom chrome chamfer
    (1.000, -0.21, 1, 0.018),
    (1.000, -0.05, 2, 0.015),    # fluted outer grip band
    (0.995,  0.00, 1, 0.015),    # bright chrome outer rim
    (0.966,  0.028, 1, 0.014),
    (0.942,  0.036, 0, 0.010),   # concentric brushed aluminum bezel top
    (0.834,  0.044, 0, 0.010),
    (0.810,  0.032, 1, 0.008),   # bright chrome inner ring step
    (0.796,  0.012, 3, 0.006),   # sloped dark-titanium chapter ring
    (FACE_R + 0.005, WELL + 0.016, 3, 0.005),
    (FACE_R - 0.015, WELL, 1),
], 0.014, segs=8)
body = lathe("Housing", body_profile, [ALU, CHROME, FLUTED, CHAPTER], steps=256)

# Enamel dial disk
face_me = bpy.data.meshes.new("Dial")
bm = bmesh.new()
bmesh.ops.create_circle(bm, cap_ends=True, segments=256, radius=FACE_R)
bm.to_mesh(face_me)
bm.free()
face = link(bpy.data.objects.new("Dial", face_me))
face.location.z = WELL + 0.0006
face.data.materials.append(DIAL)

# Subtle precision orbital rings etched on the dial face
for idx, rr in enumerate((0.675, 0.555, 0.375)):
    add_torus(f"DialRing_{idx}", rr, 0.0026 if idx == 0 else 0.0017, (0, 0, WELL + 0.0018),
              DIAL_RING, maj_seg=192, min_seg=12)

# 60 precision 3D chapter-ring tick marks
ticks_me = bpy.data.meshes.new("ChapterTicks")
bm = bmesh.new()
for i in range(60):
    ang = math.radians(i * 6.0)
    is_cardinal = (i % 15 == 0)
    is_major = (i % 5 == 0)
    length = 0.052 if is_cardinal else (0.039 if is_major else 0.023)
    width  = 0.015 if is_cardinal else (0.0095 if is_major else 0.0048)
    height = 0.008 if is_major else 0.0048
    r_mid  = 0.763 - (0.004 if is_cardinal else 0.0)
    z_mid  = WELL + 0.045 + (r_mid - FACE_R) * 0.65

    res = bmesh.ops.create_cube(bm, size=1.0)
    verts = res["verts"]
    bmesh.ops.scale(bm, vec=(length, width, height), verts=verts)
    bmesh.ops.rotate(bm, cent=(0, 0, 0), matrix=Matrix.Rotation(math.radians(-32), 3, "Y"), verts=verts)
    bmesh.ops.translate(bm, vec=(r_mid, 0, z_mid), verts=verts)
    bmesh.ops.rotate(bm, cent=(0, 0, 0), matrix=Matrix.Rotation(ang, 3, "Z"), verts=verts)
bmesh.ops.recalc_face_normals(bm, faces=bm.faces)
bm.to_mesh(ticks_me)
bm.free()
ticks_ob = link(bpy.data.objects.new("ChapterTicks", ticks_me))
ticks_ob.data.materials.append(TICK_MAT)

# 4 precision recessed micro-screws on the brushed bezel at 45°, 135°, 225°, 315°
for idx, deg in enumerate((45, 135, 225, 315)):
    rad = math.radians(deg)
    sx, sy = 0.892 * math.cos(rad), 0.892 * math.sin(rad)
    sz = 0.039
    add_torus(f"ScrewWell_{idx}", 0.0275, 0.005, (sx, sy, sz + 0.001), GUNMETAL, maj_seg=48, min_seg=12)
    sme = bpy.data.meshes.new(f"ScrewHead_{idx}")
    bm = bmesh.new()
    bmesh.ops.create_cone(bm, cap_ends=True, cap_tris=False, segments=48,
                          radius1=0.024, radius2=0.021, depth=0.008)
    for f in bm.faces:
        f.smooth = True
    bm.to_mesh(sme)
    bm.free()
    sob = link(bpy.data.objects.new(f"ScrewHead_{idx}", sme))
    sob.location = (sx, sy, sz + 0.0012)
    sob.data.materials.append(CHROME)
    sl_me = bpy.data.meshes.new(f"ScrewSlot_{idx}")
    bm = bmesh.new()
    bmesh.ops.create_cube(bm, size=1.0)
    bmesh.ops.scale(bm, vec=(0.037, 0.006, 0.0045), verts=bm.verts)
    bm.to_mesh(sl_me)
    bm.free()
    sl_ob = link(bpy.data.objects.new(f"ScrewSlot_{idx}", sl_me))
    sl_ob.location = (sx, sy, sz + 0.0048)
    sl_ob.rotation_euler = (0, 0, rad + math.radians(22))
    sl_ob.data.materials.append(GUNMETAL)

# ---------------------------------------------------------------- GitX branch emblem
# Optically balanced 3-node Git branching glyph:
#   * Root commit (bottom-left): Aqua Cyan-Sapphire
#   * Main HEAD (top-left):      Aqua Emerald
#   * Branch tip (upper-right):  Fiery Rust / Git Vermilion-Orange
C_ROOT   = Vector((-0.180, -0.355))
C_MAIN   = Vector((-0.180,  0.355))
C_BRANCH = Vector(( 0.270,  0.140))

ORB_R  = 0.144
ORB_Z  = WELL + 0.120
RAIL_R = 0.045
RAIL_Z = WELL + 0.068

def make_rail(name, pts, radius, z, mat):
    cu = bpy.data.curves.new(name, "CURVE")
    cu.dimensions = "3D"
    cu.bevel_depth = radius
    cu.bevel_resolution = 14
    cu.resolution_u = 48
    sp = cu.splines.new("BEZIER")
    sp.bezier_points.add(len(pts) - 1)
    for bp, (co, hl, hr) in zip(sp.bezier_points, pts):
        bp.co = (co.x, co.y, z)
        bp.handle_left = (hl.x, hl.y, z)
        bp.handle_right = (hr.x, hr.y, z)
    ob = link(bpy.data.objects.new(name, cu))
    ob.data.materials.append(mat)
    return ob

# Terminate rails cleanly inside the opaque socket collars (not inside the clear orbs!)
OFF_Y = ORB_R * 0.94
T_START = C_ROOT + Vector((0.0, OFF_Y))
T_END   = C_MAIN - Vector((0.0, OFF_Y))

def straight_pts(a, b):
    d = (b - a) / 3.0
    return [(a, a - d, a + d), (b, b - d, b + d)]

# Branch rail starts seamlessly at the upper-right collar of C_ROOT and sweeps into C_BRANCH
B_START = C_ROOT + Vector((0.020, OFF_Y * 0.90))
B_END   = C_BRANCH + Vector((-ORB_R * 0.85, -ORB_R * 0.44))
branch_pts = [
    (B_START, B_START - Vector((0.03, 0.16)), B_START + Vector((0.04, 0.22))),
    (B_END,   B_END   - Vector((0.19, 0.09)), B_END   + Vector((0.12, 0.06))),
]

# Dark recessed shadow channels beneath the rails
make_rail("TrunkGroove",  straight_pts(T_START, T_END), RAIL_R * 1.38, WELL + 0.008, GUNMETAL)
make_rail("BranchGroove", branch_pts,                   RAIL_R * 1.38, WELL + 0.008, GUNMETAL)

# Heavy mirror-chrome tubular rails
make_rail("TrunkRail",  straight_pts(T_START, T_END), RAIL_R, RAIL_Z, CHROME)
make_rail("BranchRail", branch_pts,                   RAIL_R, RAIL_Z, CHROME)

def make_commit_node(name, xy, gel_mat, dish_mat):
    # Stepped machined satin-steel & chrome bezel socket with an opaque colored
    # mirror-dish floor so the jewel glows purely with zero muddy rail pass-through!
    # Mats: 0=COLLAR, 1=CHROME, 2=dish_mat
    base_prof = fillet([
        (0.000, WELL + 0.001, 0),
        (ORB_R * 1.28, WELL + 0.001, 0),
        (ORB_R * 1.24, WELL + 0.032, 0, 0.008),
        (ORB_R * 1.09, WELL + 0.068, 1, 0.010),
        (ORB_R * 0.97, WELL + 0.072, 1, 0.006),
        (ORB_R * 0.86, WELL + 0.038, 2, 0.008),
        (0.000,        WELL + 0.024, 2),
    ], 0.006, segs=6)
    cup = lathe(name + "_Cup", base_prof, [COLLAR, CHROME, dish_mat], steps=128)
    cup.location = (xy.x, xy.y, 0.0)

    # Polished chrome retaining ring at the jewel equator
    add_torus(name + "_Ring", ORB_R * 1.01, 0.020, (xy.x, xy.y, WELL + 0.068), CHROME, maj_seg=128, min_seg=24)

    # Aqua gel-glass cabochon orb
    me = bpy.data.meshes.new(name + "_Orb")
    bm = bmesh.new()
    bmesh.ops.create_uvsphere(bm, u_segments=96, v_segments=48, radius=ORB_R)
    bmesh.ops.scale(bm, vec=(1.0, 1.0, 0.86), verts=bm.verts)
    for f in bm.faces:
        f.smooth = True
    bm.to_mesh(me)
    bm.free()
    ob = link(bpy.data.objects.new(name + "_Orb", me))
    ob.location = (xy.x, xy.y, ORB_Z)
    ob.data.materials.append(gel_mat)
    return ob

make_commit_node("Root",   C_ROOT,   GEL_CYAN,   DISH_CYAN)
make_commit_node("Main",   C_MAIN,   GEL_GREEN,  DISH_GREEN)
make_commit_node("Branch", C_BRANCH, GEL_ORANGE, DISH_ORANGE)

# ---------------------------------------------------------------- domed watch crystal
def crystal_profile():
    R = FACE_R + 0.070
    sag = 0.165
    rs = (R * R + sag * sag) / (2.0 * sag)
    base = 0.018
    prof = []
    n = 64
    for i in range(n + 1):
        a = math.asin(R / rs) * (i / n)
        prof.append((rs * math.sin(a), base + sag - rs * (1.0 - math.cos(a)), 0))
    return prof

if CRYSTAL_STRENGTH > 0:
    dome = lathe("WatchCrystal", crystal_profile(), [CRYSTAL], steps=256)

# ---------------------------------------------------------------- grounding & shadow catcher
bpy.context.view_layer.update()
minz = min((body.matrix_world @ v.co).z for v in body.data.vertices)
rig.location.z = -minz + 0.002
bpy.context.view_layer.update()

bpy.ops.mesh.primitive_plane_add(size=12.0, location=(0.0, 0.0, 0.0))
ground = bpy.context.active_object
ground.name = "DeskShadowCatcher"
ground.is_shadow_catcher = True

# ---------------------------------------------------------------- camera
centre = rig.matrix_world @ Vector((0.0, 0.0, -0.07))
cam_data = bpy.data.cameras.new("Cam")
cam_data.lens = 98.0
cam_data.sensor_width = 36.0
cam = bpy.data.objects.new("Cam", cam_data)
scene.collection.objects.link(cam)
scene.camera = cam

target = bpy.data.objects.new("Target", None)
scene.collection.objects.link(target)
target.location = centre + Vector((0.0, 0.0, -0.06))

elev = math.radians(CAM_ELEV)
cam.location = target.location + Vector((0.0, -math.cos(elev) * CAM_DIST, math.sin(elev) * CAM_DIST))
tr = cam.constraints.new("TRACK_TO")
tr.target = target
tr.track_axis = "TRACK_NEGATIVE_Z"
tr.up_axis = "UP_Y"

# ---------------------------------------------------------------- studio lighting
# High-contrast Apple studio product environment:
#  * Crisp dark negative-fill bands alternating with bright silver horizon bands
#  * Gives mirror chrome & brushed aluminum dramatic dark-to-bright transitions
#  * Subtle neutral-grey desk bounce at the bottom (never pitch black!)
world = bpy.data.worlds.new("StudioWorld")
scene.world = world
wnt = ensure_nodes(world)
bg = next(n for n in wnt.nodes if n.type == "BACKGROUND")

wtc = wnt.nodes.new("ShaderNodeTexCoord")
wsep = wnt.nodes.new("ShaderNodeSeparateXYZ")
wnt.links.new(wtc.outputs["Generated"], wsep.inputs[0])

wmr = wnt.nodes.new("ShaderNodeMapRange")
wmr.inputs["From Min"].default_value = -1.0
wmr.inputs["From Max"].default_value = 1.0
wnt.links.new(wsep.outputs["Z"], wmr.inputs["Value"])

wramp = wnt.nodes.new("ShaderNodeValToRGB")
cr = wramp.color_ramp
stops = [
    (0.00, (0.18, 0.19, 0.22)),   # controlled studio desk floor bounce
    (0.30, (0.04, 0.045, 0.06)),  # deep charcoal negative-fill band below horizon
    (0.47, (0.012, 0.015, 0.025)),# razor-dark horizon undercut (makes chrome gleam!)
    (0.502,(0.65, 0.70, 0.78)),   # bright crisp horizon reflection line
    (0.56, (0.10, 0.11, 0.14)),   # cool slate mid-wall
    (0.74, (0.03, 0.035, 0.05)),  # upper negative-fill contrast strip
    (0.89, (0.45, 0.48, 0.54)),   # overhead studio canopy edge
    (1.00, (0.78, 0.80, 0.84)),
]
while len(cr.elements) < len(stops):
    cr.elements.new(0.5)
for el, (pos, col) in zip(cr.elements, stops):
    el.position = pos
    el.color = (*col, 1.0)
wnt.links.new(wmr.outputs["Result"], wramp.inputs["Fac"])
wnt.links.new(wramp.outputs["Color"], bg.inputs["Color"])
bg.inputs["Strength"].default_value = 0.88

def softbox(name, loc, size, strength, color=(1, 1, 1), aim=None, falloff=(0.35, 0.35),
            ramp=0.0, diffuse=True, glossy=True):
    w, h = size
    me = bpy.data.meshes.new(name)
    bm = bmesh.new()
    bmesh.ops.create_grid(bm, x_segments=1, y_segments=1, size=0.5)
    bmesh.ops.scale(bm, vec=(w, h, 1.0), verts=bm.verts)
    bm.to_mesh(me)
    bm.free()
    ob = bpy.data.objects.new(name, me)
    scene.collection.objects.link(ob)
    ob.location = loc
    aim_v = Vector(aim) if aim else target.location
    ob.rotation_euler = (aim_v - Vector(loc)).to_track_quat("Z", "Y").to_euler()
    ob.visible_camera = False
    ob.visible_shadow = False
    ob.visible_diffuse = diffuse
    ob.visible_glossy = glossy
    ob.visible_transmission = glossy

    m = bpy.data.materials.new(name)
    nt = ensure_nodes(m)
    for n in list(nt.nodes):
        if n.type != "OUTPUT_MATERIAL":
            nt.nodes.remove(n)
    out = output_node(m)
    em = nt.nodes.new("ShaderNodeEmission")
    em.inputs["Color"].default_value = (*color, 1.0)

    tc = nt.nodes.new("ShaderNodeTexCoord")
    sep = nt.nodes.new("ShaderNodeSeparateXYZ")
    nt.links.new(tc.outputs["Generated"], sep.inputs[0])

    def feather(sock, f):
        a = nt.nodes.new("ShaderNodeMapRange")
        a.interpolation_type = "SMOOTHERSTEP"
        a.inputs["From Min"].default_value = 0.0
        a.inputs["From Max"].default_value = f
        nt.links.new(sock, a.inputs["Value"])
        b = nt.nodes.new("ShaderNodeMapRange")
        b.interpolation_type = "SMOOTHERSTEP"
        b.inputs["From Min"].default_value = 1.0
        b.inputs["From Max"].default_value = 1.0 - f
        nt.links.new(sock, b.inputs["Value"])
        mm = nt.nodes.new("ShaderNodeMath")
        mm.operation = "MULTIPLY"
        nt.links.new(a.outputs[0], mm.inputs[0])
        nt.links.new(b.outputs[0], mm.inputs[1])
        return mm.outputs[0]

    fx = feather(sep.outputs["X"], falloff[0])
    fy = feather(sep.outputs["Y"], falloff[1])
    mm = nt.nodes.new("ShaderNodeMath")
    mm.operation = "MULTIPLY"
    nt.links.new(fx, mm.inputs[0])
    nt.links.new(fy, mm.inputs[1])

    gr = nt.nodes.new("ShaderNodeMapRange")
    gr.inputs["To Min"].default_value = 1.0 - ramp
    nt.links.new(sep.outputs["Y"], gr.inputs["Value"])

    m2 = nt.nodes.new("ShaderNodeMath")
    m2.operation = "MULTIPLY"
    nt.links.new(mm.outputs[0], m2.inputs[0])
    nt.links.new(gr.outputs[0], m2.inputs[1])

    m3 = nt.nodes.new("ShaderNodeMath")
    m3.operation = "MULTIPLY"
    m3.inputs[1].default_value = strength
    nt.links.new(m2.outputs[0], m3.inputs[0])
    nt.links.new(m3.outputs[0], em.inputs["Strength"])
    nt.links.new(em.outputs[0], out.inputs["Surface"])
    ob.data.materials.append(m)
    return ob

def area_light(name, loc, size, energy, color=(1, 1, 1), aim=None, glossy=False):
    ld = bpy.data.lights.new(name, "AREA")
    ld.shape = "RECTANGLE"
    ld.size, ld.size_y = size
    ld.energy = energy
    ld.color = color
    lo = bpy.data.objects.new(name, ld)
    scene.collection.objects.link(lo)
    lo.location = loc
    aim_v = Vector(aim) if aim else target.location
    lo.rotation_euler = (aim_v - Vector(loc)).to_track_quat("-Z", "Y").to_euler()
    lo.visible_glossy = glossy
    lo.visible_transmission = glossy
    return lo

T = target.location

# 1. HIG Overhead Key + Soft Ambient Fill: rich contact shadow + silky soft drop shadow
area_light("OverheadShadowKey", T + Vector((0.0, -0.15, 6.2)), (2.8, 2.2), 340.0, (1.0, 0.99, 0.98), glossy=False)
area_light("OverheadSoftFill",  T + Vector((0.0, -0.60, 5.5)), (7.2, 6.0), 150.0, (0.96, 0.98, 1.00), glossy=False)

# 2. Classic Aqua Crystal Crescent Canopy: wide overhead softbox positioned to sweep
#    a silky curved translucent sheen across the top arc of the crystal & paint crisp
#    overhead specular glints on the crown of all three Aqua jewels (no stray blobs!)
softbox("AquaGlossCanopy", T + Vector((0.0, -1.55, 4.15)), (5.4, 2.1), 9.6, (0.98, 0.99, 1.0),
        aim=T + Vector((0.0, 0.0, 0.15)), falloff=(0.40, 0.46), ramp=0.68)

# 3. Sharp Rim Strip Cards (give the brushed aluminum & chrome edges crisp white highlights)
softbox("RimLeft",  T + Vector((-3.5, 0.4, 1.7)), (0.65, 4.4), 13.5, (0.86, 0.94, 1.0), falloff=(0.45, 0.30))
softbox("RimRight", T + Vector(( 3.5, 0.4, 1.7)), (0.65, 4.4), 13.5, (1.0, 0.96, 0.90), falloff=(0.45, 0.30))

# 4. Centered High Overhead Specular Core (merges seamlessly into the upper crescent,
#    giving each orb a crisp, centered wet Aqua specular glint with zero stray pills)
softbox("OverheadCrownGlint", T + Vector((0.0, -1.85, 4.45)), (2.6, 0.85), 14.0, (1.0, 1.0, 1.0),
        aim=T + Vector((0.0, 0.0, 0.10)), falloff=(0.48, 0.48), diffuse=False, glossy=True)

# 5. Subtle Desk Floor Bounce Strip under the front lip (keeps bottom metal sculptural)
softbox("DeskBounce", T + Vector((0.0, -3.0, -1.55)), (3.8, 0.9), 3.6, (0.94, 0.96, 1.0),
        aim=T + Vector((0.0, 0.0, -0.35)), falloff=(0.40, 0.45))

# ---------------------------------------------------------------- render settings
r = scene.render
r.engine = "CYCLES"
scene.cycles.device = "CPU"
scene.cycles.samples = SAMPLES
scene.cycles.use_adaptive_sampling = True
scene.cycles.adaptive_threshold = 0.008
scene.cycles.use_denoising = True
scene.cycles.max_bounces = 16
scene.cycles.transmission_bounces = 16
scene.cycles.glossy_bounces = 8
scene.cycles.transparent_max_bounces = 8
scene.cycles.caustics_refractive = True
scene.cycles.caustics_reflective = True

r.film_transparent = True
r.resolution_x = r.resolution_y = RES
r.resolution_percentage = 100
r.image_settings.file_format = "PNG"
r.image_settings.color_mode = "RGBA"
r.image_settings.color_depth = "8"

vs = scene.view_settings
try:
    vs.view_transform = "AgX"
    looks = [i.identifier for i in vs.bl_rna.properties["look"].enum_items]
    want = next((l for l in looks if "Punchy" in l), None) or next((l for l in looks if "High" in l), None)
    if want:
        vs.look = want
    vs.exposure = 0.30
except TypeError as e:
    print("View transform warning:", e)

r.filepath = OUT
if SAVE_BLEND:
    bpy.ops.wm.save_as_mainfile(filepath=SAVE_BLEND)
bpy.ops.render.render(write_still=True)
print("WROTE", OUT)
