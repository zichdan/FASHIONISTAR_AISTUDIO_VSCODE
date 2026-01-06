"use client";
import React, { useRef, useEffect } from "react";

interface ModalProps {
  children: React.ReactNode;
  isOpen: boolean;
}

const Modal: React.FC<ModalProps> = ({ children, isOpen }) => {
  const dialogRef = useRef<HTMLDialogElement | null>(null);

  useEffect(() => {
    const dialog = dialogRef.current;

    if (isOpen) {
      dialog?.showModal();
      document.body.style.overflow = "hidden";
    } else {
      dialog?.close();
      document.body.style.overflow = "auto";
    }

    // Cleanup when component unmounts or isOpen changes
    return () => {
      dialog?.close();
      document.body.style.overflow = "auto";
    };
  }, [isOpen]);

  return (
    <dialog
      ref={dialogRef}
      className="z-50 outline-none rounded-xl bg-white overflow-y-auto"
    >
      {children}
      <style jsx>{`
        dialog::backdrop {
          background: rgba(0, 0, 0, 0.5);
        }
      `}</style>
    </dialog>
  );
};

export default Modal;
