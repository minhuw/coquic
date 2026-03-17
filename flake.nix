{
  description = "Development environment for coquic";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
  };

  outputs = { nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
      };
    in {
      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          zig
          clang-tools
          lldb
          pkg-config
        ];

        shellHook = ''
          echo "coquic dev shell ready. Run: zig build"
        '';
      };
    };
}
