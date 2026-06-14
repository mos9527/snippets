import bpy

def setup_child_armature_modifiers():
    # Get the currently active object
    armature = bpy.context.active_object
    
    # Verify that an object is selected and that it is an Armature
    if not armature or armature.type != 'ARMATURE':
        print("Error: Please select an Armature object first.")
        return

    modified_count = 0
    
    # Loop through all objects parented to this armature
    for child in armature.children:
        # Proceed only if the child is a Mesh
        if child.type == 'MESH':
            # Look for an existing Armature modifier
            arm_mod = next((mod for mod in child.modifiers if mod.type == 'ARMATURE'), None)
            
            # If it doesn't exist, create a new one
            if not arm_mod:
                arm_mod = child.modifiers.new(name="Armature", type='ARMATURE')
            
            # Link the modifier to the parent armature
            arm_mod.object = armature
            modified_count += 1
            
    print(f"Success: Updated Armature modifiers for {modified_count} child meshes.")

# Run the function
setup_child_armature_modifiers()